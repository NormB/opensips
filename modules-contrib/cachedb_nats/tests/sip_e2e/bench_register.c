/*
 * bench_register.c -- multi-threaded SIP REGISTER load generator
 *
 * Drop-in replacement for the bash drive loop in bench_ul_register.sh.
 * The bash version forks `sipsak` per call plus an `awk` fork per
 * iteration for float-sleep pacing -- a 7.2 ms/iter floor that caps
 * effective rate at ~140 RPS regardless of OpenSIPS performance.
 *
 * This binary opens W persistent UDP sockets (one per worker thread),
 * builds REGISTER messages with a fast format-once / patch-fields
 * scheme, paces the global send queue with a token-bucket clock, and
 * captures per-call wall-clock latency with CLOCK_MONOTONIC nanosecond
 * resolution.  No fork-exec per call, no awk, no shell sleep.
 *
 * Usage:
 *   bench_register --target host:port --n 10000 --rps 200 \
 *                  --aor-space 10000 [--workers 8] [--timeout-ms 1000] \
 *                  [--user-prefix bench] [--out latencies.txt]
 *
 * Output (single line to stdout):
 *   elapsed=NN.NNNs eff_rps=NNN.N p50=NNms p95=NNms p99=NNms max=NNms ok=N err=N
 *
 * Latencies (microseconds, one per line) are appended to OUT.  When OUT
 * is omitted, latencies are still tracked in memory for percentiles but
 * not persisted -- consumers like the wrapper sort them themselves.
 *
 * Compile:
 *   cc -O2 -Wall -pthread -o bench_register bench_register.c
 *
 * Why C and not sipp / Go / Rust?  sipp is XML-driven and the rate
 * model doesn't cleanly express "exactly N total calls cycled across
 * AOR_SPACE users."  Go / Rust would work but add a build-system
 * dependency; this tree already builds C.  At 1000 RPS the dominant
 * cost is socket I/O, not language overhead.
 */

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

/* --- config / globals --------------------------------------------- */

static const char *opt_host       = "127.0.0.1";
static int         opt_port       = 5072;
static int         opt_n          = 10000;
static int         opt_rps        = 200;
static int         opt_aor_space  = 10000;
static int         opt_workers    = 8;
static int         opt_timeout_ms = 1000;
static const char *opt_user_pfx   = "bench";
static const char *opt_out        = NULL;
static int         opt_verbose    = 0;

static atomic_int     g_next_call;     /* next call index to claim */
static atomic_int     g_done_ok;
static atomic_int     g_done_err;

static struct sockaddr_in g_target;

/* Latency table -- index = call_id, value = wallclock micros, or 0 if
 * the call timed out / failed.  Allocated up-front for opt_n entries
 * so workers can write lock-free into their own slot. */
static uint32_t       *g_lat_us;

/* Pacing: monotonic-clock target for the next send across the whole
 * fleet of workers.  Workers atomically advance it. */
static atomic_uint_fast64_t g_next_send_ns;
static int64_t              g_period_ns;   /* 1e9 / RPS */

/* --- helpers ------------------------------------------------------- */

static int64_t now_ns(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

static void die(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	fprintf(stderr, "bench_register: ");
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
	va_end(ap);
	exit(2);
}

/* High-resolution sleep until the given monotonic deadline.  Returns
 * 0 if we slept, 1 if the deadline already passed. */
static int sleep_until_ns(int64_t deadline_ns)
{
	int64_t now = now_ns();
	if (deadline_ns <= now)
		return 1;
	struct timespec req = {
		.tv_sec  = (deadline_ns - now) / 1000000000LL,
		.tv_nsec = (deadline_ns - now) % 1000000000LL,
	};
	while (nanosleep(&req, &req) == -1 && errno == EINTR)
		;
	return 0;
}

/* Build a minimal REGISTER targetting opt_host:opt_port for
 * "<user_pfx>N" with a unique branch / tag / call-id derived from
 * call_idx.  Returns the byte length of the rendered message in buf. */
static int build_register(char *buf, size_t buflen,
                          int worker_id, int call_idx,
                          int local_port)
{
	int user_idx = call_idx % opt_aor_space;
	/* Random-ish but reproducible per call_idx so retransmits collide
	 * if the harness is rerun with the same seed.  We never retransmit
	 * here, so collisions don't matter. */
	uint64_t mix = ((uint64_t)worker_id << 40) ^
	               ((uint64_t)call_idx << 16) ^
	               (uint64_t)now_ns();
	int n = snprintf(buf, buflen,
		"REGISTER sip:%s:%d SIP/2.0\r\n"
		"Via: SIP/2.0/UDP 127.0.0.1:%d;branch=z9hG4bK%016lx;rport\r\n"
		"Max-Forwards: 70\r\n"
		"From: <sip:%s%d@%s>;tag=%016lx\r\n"
		"To: <sip:%s%d@%s>\r\n"
		"Call-ID: %016lx@bench\r\n"
		"CSeq: 1 REGISTER\r\n"
		"Contact: <sip:%s%d@127.0.0.1:%d>;expires=60\r\n"
		"User-Agent: bench_register/1\r\n"
		"Content-Length: 0\r\n"
		"\r\n",
		opt_host, opt_port,
		local_port, mix,
		opt_user_pfx, user_idx, opt_host, mix ^ 0xa5a5a5a5a5a5a5a5UL,
		opt_user_pfx, user_idx, opt_host,
		mix ^ 0x5a5a5a5a5a5a5a5aUL,
		opt_user_pfx, user_idx, local_port);
	if (n >= (int)buflen)
		return -1;
	return n;
}

/* Parse a SIP response: returns the integer status code (e.g. 200) or
 * -1 if the buffer doesn't look like a SIP response at all. */
static int parse_status(const char *buf, int len)
{
	if (len < 12 || memcmp(buf, "SIP/2.0 ", 8) != 0)
		return -1;
	int code = 0;
	for (int i = 8; i < 12 && i < len; i++) {
		if (buf[i] < '0' || buf[i] > '9') break;
		code = code * 10 + (buf[i] - '0');
	}
	return code;
}

/* --- worker -------------------------------------------------------- */

struct worker_arg {
	int id;
};

static void *worker_main(void *vp)
{
	struct worker_arg *wa = vp;
	int id = wa->id;

	/* Per-worker UDP socket bound to an ephemeral port. */
	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0)
		die("socket: %s", strerror(errno));

	struct sockaddr_in la = { .sin_family = AF_INET };
	la.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (bind(sock, (struct sockaddr *)&la, sizeof(la)) != 0)
		die("bind worker %d: %s", id, strerror(errno));

	socklen_t lalen = sizeof(la);
	getsockname(sock, (struct sockaddr *)&la, &lalen);
	int local_port = ntohs(la.sin_port);

	struct timeval tv = {
		.tv_sec  = opt_timeout_ms / 1000,
		.tv_usec = (opt_timeout_ms % 1000) * 1000,
	};
	if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0)
		die("setsockopt worker %d: %s", id, strerror(errno));

	/* Connect-on-UDP narrows recv to packets from the target only. */
	if (connect(sock, (struct sockaddr *)&g_target, sizeof(g_target)) != 0)
		die("connect worker %d: %s", id, strerror(errno));

	char snd_buf[4096];
	char rcv_buf[4096];

	for (;;) {
		int call_idx = atomic_fetch_add(&g_next_call, 1);
		if (call_idx >= opt_n)
			break;

		/* Pace: claim the next slot on the global send schedule.
		 * Each call advances g_next_send_ns by g_period_ns so the
		 * fleet maintains an aggregate rate of opt_rps. */
		int64_t my_send_at = (int64_t)atomic_fetch_add(
			&g_next_send_ns, (uint_fast64_t)g_period_ns);
		sleep_until_ns(my_send_at);

		int snd_len = build_register(snd_buf, sizeof(snd_buf),
				id, call_idx, local_port);
		if (snd_len < 0) {
			atomic_fetch_add(&g_done_err, 1);
			continue;
		}

		int64_t t0 = now_ns();
		ssize_t s = send(sock, snd_buf, snd_len, 0);
		if (s != snd_len) {
			atomic_fetch_add(&g_done_err, 1);
			continue;
		}

		/* Consume responses until we see a final (>= 200).  100/180
		 * are provisional; OpenSIPS may emit 100 Trying for some
		 * deployments though the bench cfg doesn't stateful-process. */
		int final_code = 0;
		for (int i = 0; i < 4; i++) {
			ssize_t r = recv(sock, rcv_buf, sizeof(rcv_buf), 0);
			if (r <= 0) {
				/* timeout or error */
				break;
			}
			int code = parse_status(rcv_buf, (int)r);
			if (code <= 0) continue;
			if (code >= 200) { final_code = code; break; }
		}

		int64_t t1 = now_ns();
		uint32_t lat_us = (uint32_t)((t1 - t0) / 1000);

		if (final_code >= 200 && final_code < 300) {
			g_lat_us[call_idx] = lat_us;
			atomic_fetch_add(&g_done_ok, 1);
		} else {
			atomic_fetch_add(&g_done_err, 1);
		}
	}

	close(sock);
	return NULL;
}

/* --- stats --------------------------------------------------------- */

static int cmp_u32(const void *a, const void *b)
{
	uint32_t x = *(const uint32_t *)a, y = *(const uint32_t *)b;
	return (x > y) - (x < y);
}

static void emit_stats(int64_t elapsed_ns)
{
	int ok = atomic_load(&g_done_ok);
	int err = atomic_load(&g_done_err);

	/* Compact non-zero latencies for percentile calc. */
	uint32_t *lat = malloc(sizeof(uint32_t) * (size_t)ok);
	int j = 0;
	for (int i = 0; i < opt_n; i++)
		if (g_lat_us[i] > 0)
			lat[j++] = g_lat_us[i];
	qsort(lat, (size_t)j, sizeof(uint32_t), cmp_u32);

	uint32_t p50 = j ? lat[(int)(0.50 * j)] : 0;
	uint32_t p95 = j ? lat[(int)(0.95 * j)] : 0;
	uint32_t p99 = j ? lat[(int)(0.99 * j)] : 0;
	uint32_t mx  = j ? lat[j - 1] : 0;

	double secs = elapsed_ns / 1e9;
	double rps  = secs > 0 ? ok / secs : 0;

	printf("elapsed=%.3fs eff_rps=%.1f p50=%uus p95=%uus p99=%uus max=%uus "
	       "ok=%d err=%d\n",
	       secs, rps, p50, p95, p99, mx, ok, err);

	if (opt_out) {
		FILE *f = fopen(opt_out, "w");
		if (f) {
			for (int i = 0; i < j; i++)
				fprintf(f, "%u\n", lat[i]);
			fclose(f);
		}
	}

	free(lat);
}

/* --- main ---------------------------------------------------------- */

static void usage(void)
{
	fprintf(stderr,
"Usage: bench_register --target HOST:PORT --n N --rps RPS \\\n"
"                     --aor-space AS [--workers W] [--timeout-ms MS] \\\n"
"                     [--user-prefix S] [--out latencies.txt] [-v]\n");
	exit(2);
}

int main(int argc, char **argv)
{
	for (int i = 1; i < argc; i++) {
		const char *a = argv[i];
		if      (!strcmp(a, "--target") && i+1<argc) {
			char *colon = strchr(argv[++i], ':');
			if (!colon) die("bad --target (need host:port)");
			*colon = 0;
			opt_host = strdup(argv[i]);
			opt_port = atoi(colon + 1);
		}
		else if (!strcmp(a, "--n")          && i+1<argc) opt_n          = atoi(argv[++i]);
		else if (!strcmp(a, "--rps")        && i+1<argc) opt_rps        = atoi(argv[++i]);
		else if (!strcmp(a, "--aor-space")  && i+1<argc) opt_aor_space  = atoi(argv[++i]);
		else if (!strcmp(a, "--workers")    && i+1<argc) opt_workers    = atoi(argv[++i]);
		else if (!strcmp(a, "--timeout-ms") && i+1<argc) opt_timeout_ms = atoi(argv[++i]);
		else if (!strcmp(a, "--user-prefix")&& i+1<argc) opt_user_pfx   = argv[++i];
		else if (!strcmp(a, "--out")        && i+1<argc) opt_out        = argv[++i];
		else if (!strcmp(a, "-v"))                       opt_verbose    = 1;
		else usage();
	}

	if (opt_n <= 0)         die("--n must be > 0");
	if (opt_rps <= 0)       die("--rps must be > 0");
	if (opt_aor_space <= 0) die("--aor-space must be > 0");
	if (opt_workers <= 0)   die("--workers must be > 0");

	memset(&g_target, 0, sizeof(g_target));
	g_target.sin_family = AF_INET;
	g_target.sin_port   = htons(opt_port);
	if (inet_pton(AF_INET, opt_host, &g_target.sin_addr) != 1)
		die("--target host must be a dotted-quad IPv4");

	g_lat_us = calloc((size_t)opt_n, sizeof(uint32_t));
	if (!g_lat_us) die("oom");

	g_period_ns = 1000000000LL / opt_rps;
	atomic_store(&g_next_send_ns, (uint_fast64_t)now_ns());
	atomic_store(&g_next_call,    0);
	atomic_store(&g_done_ok,      0);
	atomic_store(&g_done_err,     0);

	if (opt_verbose) {
		fprintf(stderr,
		    "bench_register: target=%s:%d n=%d rps=%d aor_space=%d "
		    "workers=%d timeout_ms=%d period_ns=%ld\n",
		    opt_host, opt_port, opt_n, opt_rps, opt_aor_space,
		    opt_workers, opt_timeout_ms, g_period_ns);
	}

	int64_t t_start = now_ns();

	pthread_t *threads = calloc((size_t)opt_workers, sizeof(pthread_t));
	struct worker_arg *args = calloc((size_t)opt_workers, sizeof(*args));
	for (int i = 0; i < opt_workers; i++) {
		args[i].id = i;
		if (pthread_create(&threads[i], NULL, worker_main, &args[i]) != 0)
			die("pthread_create #%d: %s", i, strerror(errno));
	}
	for (int i = 0; i < opt_workers; i++)
		pthread_join(threads[i], NULL);

	int64_t t_end = now_ns();
	emit_stats(t_end - t_start);

	free(threads);
	free(args);
	free(g_lat_us);
	return 0;
}
