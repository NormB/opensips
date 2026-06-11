/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

/*
 * nats_persist.c -- JSON snapshot persistence for the handle registry.
 *
 * Design notes:
 *   - Whole-file replace-via-rename.  The writer serializes the full
 *     registry to a cJSON array, prints it, dumps it to a tempfile in
 *     the target directory, fsync()s, then rename()s over the target.
 *     rename(2) is atomic on POSIX within a single filesystem.
 *   - Debounce: schedule_write() just bumps a "dirty" counter + sets
 *     the latest dirty timestamp under a mutex.  The writer thread
 *     wakes every 100 ms and writes only when the newest dirty mark is
 *     at least 500 ms old (so a burst of 10 binds coalesces into one
 *     write).
 *   - Writer is a pthread -- we cannot use opensips' proc model here
 *     because the dirty-flag writers are any SIP worker / MI handler,
 *     and the write latency is not worth a dedicated process.
 *   - Rehydrate converts each JSON object back into a canonical k=v
 *     config string and hands it to nats_handle_parse() so all
 *     validation lives in one place (parser was already audited).
 *
 * Only bind-time config fields are persisted.  Runtime counters,
 * subscriptions, ack tokens, and the bind-order index are ephemeral.
 */

#ifdef TEST_SHIM
#include "tests/test_shim.h"
#else
#include "../../mem/shm_mem.h"
#include "../../dprint.h"
#endif

#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "../../lib/cJSON.h"

#include "nats_persist.h"
#include "nats_handle_registry.h"
#include "nats_handle_parse.h"

/* ── monotonic-ish time helper in milliseconds ─────────────────── */

static long long now_ms(void)
{
	struct timespec ts;
#ifdef CLOCK_MONOTONIC
	clock_gettime(CLOCK_MONOTONIC, &ts);
#else
	clock_gettime(CLOCK_REALTIME, &ts);
#endif
	return (long long)ts.tv_sec * 1000LL + ts.tv_nsec / 1000000LL;
}

/* ── module state ─────────────────────────────────────────────── */

#define NATS_PERSIST_DEBOUNCE_MS   500
#define NATS_PERSIST_TICK_MS       100

/* Cap on the bytes slurp_file() will allocate for a persist snapshot.
 * 10 MiB is far larger than any realistic registry dump but small
 * enough to refuse to load a symlinked log/dump file or a corrupted
 * persist target.  Caller logs an error if exceeded. */
#define NATS_PERSIST_MAX_FILE_BYTES   (10L * 1024 * 1024)

typedef struct nats_persist_state {
	char           *path;        /* malloc'd absolute path */

	pthread_t       writer;
	int             writer_running;

	pthread_mutex_t lock;
	pthread_cond_t  cond;

	int             stop;        /* writer-thread exit flag */

	int             init_done;
} nats_persist_state_t;

static nats_persist_state_t g_state = {
	.path           = NULL,
	.writer_running = 0,
	.stop           = 0,
	.init_done      = 0,
};

/* Dirty-tracking lives in SHM so nats_persist_schedule_write() works
 * from ANY process.  The writer pthread runs only in the attendant
 * (created in nats_persist_init, pre-fork); SIP workers and the MI
 * process call schedule_write from nats_registry_bind/unbind, so the
 * "dirty" signal must cross the fork boundary.  These two atomics are
 * shm_malloc'd pre-fork (every child shares one copy) and the writer
 * polls them on each NATS_PERSIST_TICK_MS wake.  The per-process
 * pthread condvar can only deliver an *immediate* wake for a
 * schedule_write made in the attendant itself, so that is now just a
 * latency optimisation rather than the delivery mechanism. */
typedef struct nats_persist_shared {
	_Atomic int       dirty;       /* 1 = pending write */
	_Atomic long long dirty_ms;    /* now_ms() when dirty was last set */
} nats_persist_shared_t;

static nats_persist_shared_t *g_shared;   /* SHM, shared across fork */

static inline void persist_mark_dirty(void)
{
	if (!g_shared)
		return;
	/* stamp first so a reader observing dirty=1 sees a sane dirty_ms */
	atomic_store_explicit(&g_shared->dirty_ms, now_ms(),
		memory_order_relaxed);
	atomic_store_explicit(&g_shared->dirty, 1, memory_order_relaxed);
}

/* ── helpers: enum <-> string ─────────────────────────────────── */

static const char *type_to_str(nats_consumer_type_e t)
{
	switch (t) {
		case NATS_CONSUMER_DURABLE:   return "durable";
		case NATS_CONSUMER_EPHEMERAL: return "ephemeral";
		case NATS_CONSUMER_ORDERED:   return "ordered";
	}
	return "unknown";
}

static const char *deliver_to_str(nats_deliver_policy_e d)
{
	switch (d) {
		case NATS_DELIVER_ALL:              return "all";
		case NATS_DELIVER_LAST:             return "last";
		case NATS_DELIVER_NEW:              return "new";
		case NATS_DELIVER_LAST_PER_SUBJECT: return "last_per_subject";
		case NATS_DELIVER_BY_START_SEQ:     return "by_start_seq";
		case NATS_DELIVER_BY_START_TIME:    return "by_start_time";
	}
	return "all";
}

static const char *ack_to_str(nats_ack_policy_e a)
{
	switch (a) {
		case NATS_ACK_EXPLICIT: return "explicit";
		case NATS_ACK_NONE:     return "none";
		case NATS_ACK_ALL:      return "all";
	}
	return "explicit";
}

static const char *replay_to_str(nats_replay_policy_e r)
{
	return r == NATS_REPLAY_ORIGINAL ? "original" : "instant";
}

/* ── serialize one handle → cJSON object ──────────────────────── */

/* Helper: add "k":"v.*s"-style entry when the str is non-empty. */
static void add_str_if(cJSON *obj, const char *key, const str *s)
{
	if (!s || s->len <= 0 || !s->s)
		return;
	cJSON_AddItemToObject(obj, key, cJSON_CreateStr(s->s, s->len));
}

struct serialize_ctx {
	cJSON *arr;
	int err;
};

static int serialize_cb(nats_handle_t *h, void *user)
{
	struct serialize_ctx *ctx = (struct serialize_ctx *)user;
	cJSON *obj;

	/* A retired handle is still physically present but should not be
	 * persisted -- if the opensips instance dies before the reaper
	 * runs we do not want to resurrect it on next start. */
	if (__atomic_load_n(&h->retire, __ATOMIC_SEQ_CST)) {
		return 0;
	}

	obj = cJSON_CreateObject();
	if (!obj) {
		ctx->err = 1;
		return -1;
	}

	add_str_if(obj, "id",       &h->id);
	add_str_if(obj, "stream",   &h->stream);

	/* consumer kind: exactly one of durable / ephemeral=true */
	if (h->type == NATS_CONSUMER_DURABLE) {
		add_str_if(obj, "durable", &h->durable);
	} else if (h->type == NATS_CONSUMER_EPHEMERAL) {
		cJSON_AddBoolToObject(obj, "ephemeral", 1);
	}
	cJSON_AddStringToObject(obj, "type", type_to_str(h->type));

	add_str_if(obj, "filter",      &h->filter);
	add_str_if(obj, "filters",     &h->filters_csv);

	/* deliver policy: only emit if not default (ALL) */
	if (h->deliver_policy != NATS_DELIVER_ALL)
		cJSON_AddStringToObject(obj, "deliver_policy",
				deliver_to_str(h->deliver_policy));
	/* uint64_t values above 2^53 lose precision when round-tripped
	 * through JSON Number (which is IEEE 754 double).  start_seq can
	 * exceed that on long-lived streams; start_time_unix_ns
	 * (nanoseconds since epoch in 2026) already exceeds 2^53 by
	 * orders of magnitude.  Serialize both as JSON strings; the
	 * rehydrate path detects the string form and uses strtoull. */
	if (h->deliver_policy == NATS_DELIVER_BY_START_SEQ && h->start_seq) {
		char numbuf[32];
		snprintf(numbuf, sizeof(numbuf), "%llu",
			(unsigned long long)h->start_seq);
		cJSON_AddStringToObject(obj, "start_seq", numbuf);
	}
	if (h->deliver_policy == NATS_DELIVER_BY_START_TIME && h->start_time_unix_ns) {
		char numbuf[32];
		snprintf(numbuf, sizeof(numbuf), "%lld",
			(long long)h->start_time_unix_ns);
		cJSON_AddStringToObject(obj, "start_time_ns", numbuf);
	}

	if (h->replay_policy != NATS_REPLAY_INSTANT)
		cJSON_AddStringToObject(obj, "replay_policy",
				replay_to_str(h->replay_policy));

	if (h->ack_policy != NATS_ACK_EXPLICIT)
		cJSON_AddStringToObject(obj, "ack_policy", ack_to_str(h->ack_policy));

	if (h->ack_wait_ms > 0)
		cJSON_AddNumberToObject(obj, "ack_wait_ms", (double)h->ack_wait_ms);
	if (h->max_deliver > 0)
		cJSON_AddNumberToObject(obj, "max_deliver", (double)h->max_deliver);
	add_str_if(obj, "backoff_csv", &h->backoff_csv);
	if (h->max_ack_pending > 0)
		cJSON_AddNumberToObject(obj, "max_ack_pending",
				(double)h->max_ack_pending);

	if (h->headers_only)
		cJSON_AddBoolToObject(obj, "headers_only", 1);
	if (h->sample_freq > 0)
		cJSON_AddNumberToObject(obj, "sample_freq", (double)h->sample_freq);
	if (h->rate_limit_bps > 0)
		cJSON_AddNumberToObject(obj, "rate_limit_bps",
				(double)h->rate_limit_bps);
	if (h->inactive_threshold_ms > 0)
		cJSON_AddNumberToObject(obj, "inactive_threshold_ms",
				(double)h->inactive_threshold_ms);

	add_str_if(obj, "js_domain",  &h->js_domain);
	add_str_if(obj, "api_prefix", &h->api_prefix);

	if (h->ring_capacity > 0)
		cJSON_AddNumberToObject(obj, "ring_capacity",
				(double)h->ring_capacity);

	/* forward-compat passthrough: copy any keys the parser stashed into
	 * extra_json back onto the object so round-trips do not strip them.
	 * extra_json is already a JSON object literal produced by the parser
	 * (e.g. {"foo":"bar","baz":"qux"}), so parse it and shallow-merge
	 * each child.  A malformed extra_json is logged and skipped -- we do
	 * not want a single bad entry to fail the whole snapshot. */
	if (h->extra_json.len > 0 && h->extra_json.s) {
		char *tmp = (char *)malloc(h->extra_json.len + 1);
		if (tmp) {
			cJSON *ex;
			memcpy(tmp, h->extra_json.s, h->extra_json.len);
			tmp[h->extra_json.len] = '\0';
			ex = cJSON_Parse(tmp);
			free(tmp);
			if (ex && (ex->type & cJSON_Object)) {
				cJSON *c;
				for (c = ex->child; c; c = c->next) {
					cJSON *dup = NULL;
					if (!c->string) continue;
					/* do not clobber a key we already emitted */
					if (cJSON_GetObjectItem(obj, c->string))
						continue;
					/* The parser stores all extras as JSON strings, so a
					 * shallow duplicate is enough -- no arrays/objects or
					 * nested structure to worry about. */
					if (c->type & cJSON_String) {
						dup = cJSON_CreateString(
								c->valuestring ? c->valuestring : "");
					} else if (c->type & cJSON_Number) {
						dup = cJSON_CreateNumber(c->valuedouble);
					} else if (c->type & cJSON_True) {
						dup = cJSON_CreateBool(1);
					} else if (c->type & cJSON_False) {
						dup = cJSON_CreateBool(0);
					}
					if (dup)
						cJSON_AddItemToObject(obj, c->string, dup);
				}
			} else {
				LM_WARN("nats_persist: extra_json for id=%.*s not a "
						"JSON object; skipping passthrough\n",
						h->id.len, h->id.s);
			}
			if (ex) cJSON_Delete(ex);
		}
	}

	cJSON_AddItemToArray(ctx->arr, obj);
	return 0;
}

/* Serialize the full registry to a freshly-malloc'd JSON string.
 * Caller frees via cJSON_PurgeString(). */
static char *serialize_registry(void)
{
	cJSON *arr;
	struct serialize_ctx ctx;
	char *out;

	arr = cJSON_CreateArray();
	if (!arr)
		return NULL;

	ctx.arr = arr;
	ctx.err = 0;

	nats_registry_foreach(serialize_cb, &ctx);

	if (ctx.err) {
		cJSON_Delete(arr);
		return NULL;
	}

	out = cJSON_Print(arr);
	cJSON_Delete(arr);
	return out;
}

/* ── write path: tempfile + fsync + rename ───────────────────── */

/* Return a malloc'd copy of the directory component of `path`.
 * Uses a scratch buffer because dirname(3) can modify its argument. */
static char *dup_dirname(const char *path)
{
	char *scratch;
	char *dir;
	char *out;
	size_t len;

	if (!path)
		return NULL;
	scratch = strdup(path);
	if (!scratch)
		return NULL;
	dir = dirname(scratch);
	len = strlen(dir);
	out = (char *)malloc(len + 1);
	if (!out) {
		free(scratch);
		return NULL;
	}
	memcpy(out, dir, len + 1);
	free(scratch);
	return out;
}

static int dir_exists(const char *dir)
{
	struct stat st;
	if (!dir || !*dir)
		return 0;
	if (stat(dir, &st) < 0)
		return 0;
	return S_ISDIR(st.st_mode) ? 1 : 0;
}

/* Write `buf` of `len` bytes to a tempfile in the same directory as
 * g_state.path, fsync it, and rename it over g_state.path.
 * Returns 0 on success, -1 on error. */
static int atomic_write(const char *buf, size_t len)
{
	char *dir = NULL;
	char *tmp = NULL;
	int   fd  = -1;
	int   rc  = -1;
	size_t dirlen;
	size_t off;

	if (!g_state.path)
		return -1;

	dir = dup_dirname(g_state.path);
	if (!dir)
		goto out;
	dirlen = strlen(dir);

	/* tmp = "<dir>/.<basename>.XXXXXX" -- but simpler: just use a
	 * fixed template off the full path since the dir already exists. */
	tmp = (char *)malloc(dirlen + sizeof("/.nats_persist.XXXXXX") + 1);
	if (!tmp)
		goto out;
	memcpy(tmp, dir, dirlen);
	memcpy(tmp + dirlen, "/.nats_persist.XXXXXX",
			sizeof("/.nats_persist.XXXXXX"));

	fd = mkstemp(tmp);
	if (fd < 0) {
		LM_ERR("nats_persist: mkstemp(%s) failed: %s\n",
				tmp, strerror(errno));
		goto out;
	}
	/* restrict permissions -- handles may contain stream/durable names
	 * that downstream ops consider sensitive. */
	(void)fchmod(fd, 0600);

	off = 0;
	while (off < len) {
		ssize_t n = write(fd, buf + off, len - off);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			LM_ERR("nats_persist: write(%s) failed: %s\n",
					tmp, strerror(errno));
			goto out;
		}
		off += (size_t)n;
	}

	if (fsync(fd) < 0) {
		LM_ERR("nats_persist: fsync(%s) failed: %s\n",
				tmp, strerror(errno));
		goto out;
	}
	close(fd);
	fd = -1;

	if (rename(tmp, g_state.path) < 0) {
		LM_ERR("nats_persist: rename(%s -> %s) failed: %s\n",
				tmp, g_state.path, strerror(errno));
		goto out;
	}
	/* tmp no longer exists; avoid unlinking it in the failure path */
	free(tmp);
	tmp = NULL;

	rc = 0;

out:
	if (fd >= 0)
		close(fd);
	if (tmp) {
		(void)unlink(tmp);
		free(tmp);
	}
	if (dir)
		free(dir);
	return rc;
}

/* Do the actual snapshot + write.  Safe to call from any context, but
 * the writer thread calls it under the non-held state lock so we do
 * not block schedule_write(). */
static int do_write(void)
{
	char *buf;
	size_t len;
	int rc;

	buf = serialize_registry();
	if (!buf) {
		LM_ERR("nats_persist: serialize failed\n");
		return -1;
	}
	len = strlen(buf);
	rc = atomic_write(buf, len);
	cJSON_PurgeString(buf);
	if (rc == 0)
		LM_DBG("nats_persist: wrote %zu bytes to %s\n", len, g_state.path);
	return rc;
}

/* ── writer thread ────────────────────────────────────────────── */

static void *writer_main(void *arg)
{
	(void)arg;

	for (;;) {
		struct timespec deadline;
		struct timespec ts_now;
		int should_write = 0;

		pthread_mutex_lock(&g_state.lock);

		/* Sleep for at most NATS_PERSIST_TICK_MS, woken early on stop
		 * or when schedule_write() decides it needs us.
		 * pthread_cond_timedwait wants CLOCK_REALTIME. */
		clock_gettime(CLOCK_REALTIME, &ts_now);
		deadline.tv_sec  = ts_now.tv_sec  + NATS_PERSIST_TICK_MS / 1000;
		deadline.tv_nsec = ts_now.tv_nsec +
			(NATS_PERSIST_TICK_MS % 1000) * 1000000LL;
		if (deadline.tv_nsec >= 1000000000LL) {
			deadline.tv_sec  += 1;
			deadline.tv_nsec -= 1000000000LL;
		}
		(void)pthread_cond_timedwait(&g_state.cond, &g_state.lock, &deadline);

		if (g_state.stop) {
			/* Flush any dirty state one last time before exiting. */
			if (atomic_load_explicit(&g_shared->dirty,
					memory_order_relaxed)) {
				atomic_store_explicit(&g_shared->dirty, 0,
					memory_order_relaxed);
				pthread_mutex_unlock(&g_state.lock);
				(void)do_write();
			} else {
				pthread_mutex_unlock(&g_state.lock);
			}
			break;
		}

		if (atomic_load_explicit(&g_shared->dirty, memory_order_relaxed)) {
			long long age = now_ms() -
				atomic_load_explicit(&g_shared->dirty_ms,
					memory_order_relaxed);
			if (age >= NATS_PERSIST_DEBOUNCE_MS) {
				should_write = 1;
				/* Claim the dirty flag.  If a writer in another
				 * process sets it again after this clear, the next
				 * tick simply writes again -- no update is lost. */
				atomic_store_explicit(&g_shared->dirty, 0,
					memory_order_relaxed);
			}
		}

		pthread_mutex_unlock(&g_state.lock);

		if (should_write) {
			if (do_write() < 0) {
				/* on failure, re-mark dirty so we retry next tick.
				 * persist_mark_dirty() re-stamps dirty_ms so the
				 * retry is debounced, not fired on the very next
				 * tick. */
				persist_mark_dirty();
			}
		}
	}

	return NULL;
}

/* ── public API ──────────────────────────────────────────────── */

int nats_persist_enabled(void)
{
	return g_state.init_done && g_state.writer_running;
}

void nats_persist_schedule_write(void)
{
	if (!g_state.init_done)
		return;
	/* Cross-process: set the SHM dirty flag the attendant's writer
	 * polls each tick.  Works from SIP workers / MI, not just the
	 * attendant. */
	persist_mark_dirty();
	/* Wake the writer immediately when called *in the attendant* (the
	 * only process whose condvar the writer waits on).  In other
	 * processes this signals a private condvar nobody waits on --
	 * harmless; the attendant's writer still picks up the SHM flag on
	 * its next tick. */
	pthread_mutex_lock(&g_state.lock);
	pthread_cond_signal(&g_state.cond);
	pthread_mutex_unlock(&g_state.lock);
}

int nats_persist_flush_now(void)
{
	int rc;

	if (!g_state.init_done)
		return 0;

	/* Clear the dirty flag, then write -- so the writer thread does not
	 * race us and produce two snapshots of the same state.  If it does
	 * win the race it will just see dirty=0 and skip. */
	atomic_store_explicit(&g_shared->dirty, 0, memory_order_relaxed);

	rc = do_write();
	if (rc < 0)
		persist_mark_dirty();
	return rc;
}

int nats_persist_init(const char *path)
{
	char *dir;

	if (g_state.init_done) {
		LM_WARN("nats_persist: already initialized\n");
		return 0;
	}
	if (!path || !*path) {
		LM_ERR("nats_persist: empty path\n");
		return -1;
	}

	dir = dup_dirname(path);
	if (!dir) {
		LM_ERR("nats_persist: dirname alloc failed\n");
		return -2;
	}
	if (!dir_exists(dir)) {
		LM_WARN("nats_persist: parent directory %s does not exist; "
				"persistence disabled for this run\n", dir);
		free(dir);
		return -1;
	}
	free(dir);

	g_state.path = strdup(path);
	if (!g_state.path) {
		LM_ERR("nats_persist: path strdup failed\n");
		return -2;
	}

	if (pthread_mutex_init(&g_state.lock, NULL) != 0) {
		LM_ERR("nats_persist: mutex init failed\n");
		free(g_state.path);
		g_state.path = NULL;
		return -2;
	}
	if (pthread_cond_init(&g_state.cond, NULL) != 0) {
		LM_ERR("nats_persist: cond init failed\n");
		pthread_mutex_destroy(&g_state.lock);
		free(g_state.path);
		g_state.path = NULL;
		return -2;
	}

	g_state.stop           = 0;
	g_state.writer_running = 0;

	/* SHM dirty-tracking, allocated pre-fork so every child shares one
	 * copy and schedule_write() from any process reaches the writer. */
	g_shared = (nats_persist_shared_t *)shm_malloc(sizeof(*g_shared));
	if (!g_shared) {
		LM_ERR("nats_persist: shm_malloc for shared state failed\n");
		pthread_cond_destroy(&g_state.cond);
		pthread_mutex_destroy(&g_state.lock);
		free(g_state.path);
		g_state.path = NULL;
		return -2;
	}
	atomic_init(&g_shared->dirty, 0);
	atomic_init(&g_shared->dirty_ms, 0);

	if (pthread_create(&g_state.writer, NULL, writer_main, NULL) != 0) {
		LM_ERR("nats_persist: thread spawn failed: %s\n", strerror(errno));
		shm_free(g_shared);
		g_shared = NULL;
		pthread_cond_destroy(&g_state.cond);
		pthread_mutex_destroy(&g_state.lock);
		free(g_state.path);
		g_state.path = NULL;
		return -2;
	}
	g_state.writer_running = 1;
	g_state.init_done      = 1;

	LM_INFO("nats_persist: initialized (path=%s, debounce=%dms)\n",
			path, NATS_PERSIST_DEBOUNCE_MS);
	return 0;
}

void nats_persist_destroy(void)
{
	if (!g_state.init_done)
		return;

	pthread_mutex_lock(&g_state.lock);
	g_state.stop = 1;
	pthread_cond_signal(&g_state.cond);
	pthread_mutex_unlock(&g_state.lock);

	if (g_state.writer_running) {
		(void)pthread_join(g_state.writer, NULL);
		g_state.writer_running = 0;
	}

	pthread_cond_destroy(&g_state.cond);
	pthread_mutex_destroy(&g_state.lock);

	if (g_shared) {
		shm_free(g_shared);
		g_shared = NULL;
	}

	if (g_state.path) {
		free(g_state.path);
		g_state.path = NULL;
	}
	g_state.init_done = 0;
}

/* ── rehydrate ───────────────────────────────────────────────── */

/* Append a "k=v" pair to an ever-growing malloc'd buffer.
 * Returns 0 on success, -1 on alloc failure or size_t overflow. */
static int append_kv(char **buf, size_t *len, size_t *cap,
		const char *k, const char *v, size_t vlen)
{
	size_t klen = strlen(k);
	size_t need;
	/* Size-arithmetic overflow on `*len + klen + vlen + 3` would
	 * wrap to a small value and skip the realloc, after which the
	 * memcpy below would overrun the buffer.  Realistic only when
	 * an attacker has staged a single ~SIZE_MAX value in the
	 * persist file (which itself implies fs-write privilege), so
	 * this is defence in depth. */
	if (__builtin_add_overflow(*len, klen, &need)
	    || __builtin_add_overflow(need, vlen, &need)
	    || __builtin_add_overflow(need, (size_t)3, &need))
		return -1;
	if (need >= *cap) {
		size_t new_cap = *cap ? *cap * 2 : 256;
		char *nb;
		while (new_cap < need) {
			size_t doubled;
			if (__builtin_mul_overflow(new_cap, (size_t)2,
					&doubled))
				return -1;
			new_cap = doubled;
		}
		nb = (char *)realloc(*buf, new_cap);
		if (!nb) return -1;
		*buf = nb;
		*cap = new_cap;
	}
	if (*len > 0)
		(*buf)[(*len)++] = ';';
	memcpy(*buf + *len, k, klen);
	*len += klen;
	(*buf)[(*len)++] = '=';
	memcpy(*buf + *len, v, vlen);
	*len += vlen;
	(*buf)[*len] = '\0';
	return 0;
}

/* Build a config string from a cJSON object.  Returns a malloc'd
 * NUL-terminated string on success, NULL on allocation failure.
 * Field validation is deferred to nats_handle_parse().
 *
 * Any unknown object keys are forwarded into the config string so the
 * parser's extra_json path can carry them forward -- this matches the
 * serializer's forward-compat stance. */
static char *build_config_from_json(cJSON *obj)
{
	char *buf = NULL;
	size_t len = 0, cap = 0;
	cJSON *c;

	for (c = obj->child; c; c = c->next) {
		char numbuf[64];
		const char *v = NULL;
		size_t vlen = 0;

		if (!c->string)
			continue;

		/* "type" is a derived serialized field -- skip, since the parser
		 * infers durable vs ephemeral from the presence of either key. */
		if (strcmp(c->string, "type") == 0)
			continue;

		if (c->type & cJSON_String) {
			v = c->valuestring ? c->valuestring : "";
			vlen = strlen(v);
			/* Defence in depth against an attacker-modified
			 * persist file.  cJSON returns a NUL-terminated C
			 * string, so a JSON \u0000 escape in the source
			 * silently truncates vlen at the embedded NUL and
			 * downstream validators only see the prefix.  Reject
			 * any field whose serialised value contains a
			 * control char (0x00..0x1F, 0x7F) -- a legitimate
			 * serialiser never emits these.  Wildcards '*' and
			 * '>' are NOT rejected because the `filter` /
			 * `filters` fields legitimately contain them per the
			 * NATS subject grammar.  ';' and '=' ARE rejected: this
			 * value is about to be spliced into the "key=value;key=value"
			 * bind-config string, so an injected ';' or '=' from a
			 * tampered persist file would forge extra config fields. */
			{
				size_t i;
				int rejected = 0;
				for (i = 0; i < vlen; i++) {
					unsigned char b = (unsigned char)v[i];
					if (b < 0x20 || b == 0x7F ||
							b == ';' || b == '=') {
						LM_WARN("nats_persist: rejecting "
							"field '%s' with illegal "
							"byte 0x%02x at offset %zu\n",
							c->string ? c->string : "?",
							b, i);
						rejected = 1;
						break;
					}
				}
				if (rejected)
					continue;
			}
		} else if (c->type & cJSON_Number) {
			/* Use %lld for integer-valued numbers so we don't print
			 * "1e+18" for fields the JSON happens to round-trip
			 * losslessly (small ints).  Fields that need uint64
			 * precision (start_seq, start_time_ns) are serialized as
			 * strings by us and arrive on the cJSON_String branch
			 * above. */
			double d = c->valuedouble;
			int n;
			if (d == (double)(long long)d) {
				n = snprintf(numbuf, sizeof(numbuf), "%lld",
					(long long)d);
			} else {
				n = snprintf(numbuf, sizeof(numbuf), "%g", d);
			}
			if (n < 0 || n >= (int)sizeof(numbuf))
				continue;
			v = numbuf;
			vlen = (size_t)n;
		} else if (c->type & cJSON_True) {
			v = "1"; vlen = 1;
		} else if (c->type & cJSON_False) {
			v = "0"; vlen = 1;
		} else {
			continue;
		}

		/* Map serialized key names onto parser-recognized ones where
		 * they differ.  The serializer uses "ack_wait_ms" but the
		 * parser accepts "ack_wait=<duration>" -- add the ms suffix so
		 * parse_duration_ms sees a valid unit. */
		if (strcmp(c->string, "ack_wait_ms") == 0) {
			char tmp[64];
			int n = snprintf(tmp, sizeof(tmp), "%.*sms",
					(int)vlen, v);
			if (n < 0 || n >= (int)sizeof(tmp))
				continue;
			if (append_kv(&buf, &len, &cap, "ack_wait", tmp, (size_t)n) < 0)
				goto oom;
			continue;
		}
		if (strcmp(c->string, "inactive_threshold_ms") == 0) {
			char tmp[64];
			int n = snprintf(tmp, sizeof(tmp), "%.*sms",
					(int)vlen, v);
			if (n < 0 || n >= (int)sizeof(tmp))
				continue;
			if (append_kv(&buf, &len, &cap,
					"inactive_threshold", tmp, (size_t)n) < 0)
				goto oom;
			continue;
		}
		if (strcmp(c->string, "backoff_csv") == 0) {
			if (append_kv(&buf, &len, &cap, "backoff", v, vlen) < 0)
				goto oom;
			continue;
		}
		if (strcmp(c->string, "rate_limit_bps") == 0) {
			if (append_kv(&buf, &len, &cap, "rate_limit", v, vlen) < 0)
				goto oom;
			continue;
		}
		if (strcmp(c->string, "start_time_ns") == 0) {
			/* The serializer keeps lossless uint64-ns on disk to dodge
			 * IEEE-754 precision loss; the bind parser only accepts
			 * RFC3339.  Bridge the two by converting back to RFC3339
			 * with 9-digit fractional seconds + 'Z' and feeding the
			 * parser via the regular `start_time` key.  parse_rfc3339_ns
			 * round-trips this back to the same int64 the
			 * serializer wrote, so the rehydrated handle matches the
			 * pre-snapshot start time exactly.
			 *
			 * On a malformed value (non-numeric, negative, or wall-
			 * clock conversion failure) skip the field and WARN so the
			 * handle still binds; the operator can reissue with an
			 * explicit start_time. */
			char         iso[64];
			char        *endp = NULL;
			long long    ns_signed;
			uint64_t     ns;
			time_t       secs;
			long         frac_ns;
			struct tm    tm;

			ns_signed = strtoll(v, &endp, 10);
			if (!endp || endp == v || *endp != '\0' || ns_signed < 0) {
				LM_WARN("nats_persist: start_time_ns '%.*s' "
					"unparseable; handle will rehydrate "
					"without start_time\n", (int)vlen, v);
				continue;
			}
			ns      = (uint64_t)ns_signed;
			secs    = (time_t)(ns / 1000000000ULL);
			frac_ns = (long)(ns % 1000000000ULL);
			if (!gmtime_r(&secs, &tm)) {
				LM_WARN("nats_persist: start_time_ns %llu out of "
					"gmtime range; handle will rehydrate "
					"without start_time\n",
					(unsigned long long)ns);
				continue;
			}
			snprintf(iso, sizeof(iso),
				"%04d-%02d-%02dT%02d:%02d:%02d.%09ldZ",
				tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
				tm.tm_hour, tm.tm_min, tm.tm_sec, frac_ns);
			if (append_kv(&buf, &len, &cap,
					"start_time", iso, strlen(iso)) < 0)
				goto oom;
			continue;
		}

		if (append_kv(&buf, &len, &cap, c->string, v, vlen) < 0)
			goto oom;
	}

	if (!buf) {
		/* Empty object -- return an empty string so the parser rejects
		 * it cleanly rather than dereferencing NULL. */
		buf = (char *)malloc(1);
		if (!buf)
			return NULL;
		buf[0] = '\0';
	}
	return buf;

oom:
	free(buf);
	return NULL;
}

/* Slurp a file into a malloc'd NUL-terminated buffer. */
static char *slurp_file(const char *path, int *out_missing)
{
	FILE *f;
	char *buf;
	long sz;

	*out_missing = 0;
	f = fopen(path, "rb");
	if (!f) {
		if (errno == ENOENT)
			*out_missing = 1;
		return NULL;
	}
	if (fseek(f, 0, SEEK_END) < 0) {
		fclose(f);
		return NULL;
	}
	sz = ftell(f);
	if (sz < 0) {
		fclose(f);
		return NULL;
	}
	if (sz > NATS_PERSIST_MAX_FILE_BYTES) {
		LM_ERR("nats_persist: %s exceeds size cap (%ld > %ld bytes); "
			"refusing to load -- check for symlink / wrong path\n",
			path, sz, (long)NATS_PERSIST_MAX_FILE_BYTES);
		fclose(f);
		return NULL;
	}
	rewind(f);

	buf = (char *)malloc((size_t)sz + 1);
	if (!buf) {
		fclose(f);
		return NULL;
	}
	if (sz > 0 && fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
		free(buf);
		fclose(f);
		return NULL;
	}
	buf[sz] = '\0';
	fclose(f);
	return buf;
}

int nats_persist_rehydrate(void)
{
	char *raw = NULL;
	cJSON *root = NULL;
	int loaded = 0;
	int missing = 0;
	int n, i;

	if (!g_state.path) {
		LM_ERR("nats_persist: rehydrate called without init\n");
		return -1;
	}

	raw = slurp_file(g_state.path, &missing);
	if (!raw) {
		if (missing) {
			LM_INFO("nats_persist: %s does not exist yet; starting empty\n",
					g_state.path);
			return 0;
		}
		LM_ERR("nats_persist: slurp(%s) failed: %s\n",
				g_state.path, strerror(errno));
		return -1;
	}

	root = cJSON_Parse(raw);
	free(raw);
	if (!root) {
		LM_ERR("nats_persist: JSON parse failed for %s\n", g_state.path);
		return -1;
	}
	if (!(root->type & cJSON_Array)) {
		LM_ERR("nats_persist: %s root is not an array\n", g_state.path);
		cJSON_Delete(root);
		return -1;
	}

	n = cJSON_GetArraySize(root);
	for (i = 0; i < n; i++) {
		cJSON *obj = cJSON_GetArrayItem(root, i);
		char *cfg;
		str cfg_s;
		const char *err = NULL;
		nats_handle_t *h;
		int rc;

		if (!obj || !(obj->type & cJSON_Object)) {
			LM_WARN("nats_persist: skipping non-object item %d\n", i);
			continue;
		}

		cfg = build_config_from_json(obj);
		if (!cfg) {
			LM_WARN("nats_persist: skipping item %d (OOM build_config)\n", i);
			continue;
		}

		cfg_s.s = cfg;
		cfg_s.len = (int)strlen(cfg);
		h = nats_handle_parse(&cfg_s, &err);
		free(cfg);
		if (!h) {
			LM_WARN("nats_persist: skipping item %d: parse error: %s\n",
					i, err ? err : "unknown");
			continue;
		}

		rc = nats_registry_bind(h);
		if (rc == 0) {
			loaded++;
		} else if (rc == -1) {
			LM_INFO("nats_persist: item %d already bound (id='%.*s'); "
					"skipping\n", i, h->id.len, h->id.s);
			nats_handle_free(h);
		} else {
			LM_WARN("nats_persist: item %d: bind failed rc=%d\n", i, rc);
			nats_handle_free(h);
		}
	}

	cJSON_Delete(root);
	return loaded;
}
