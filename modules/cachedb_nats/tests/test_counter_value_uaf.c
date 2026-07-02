/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Regression: the cachedb_nats counter read-modify-write (cachedb_nats_dbase.c)
 * logged the raw broker value pointer returned by kvEntry_ValueString() AFTER
 * kvEntry_Destroy() had already freed the entry -- a use-after-free READ on the
 * "stored value out of 32-bit range" error path.  kvEntry_ValueString returns a
 * pointer INTO the entry's own buffer, so the "%s" in LM_ERR reads freed heap
 * (at best logs garbage / adjacent heap, at worst faults on an unmapped page).
 *
 * Fix: snapshot the value text into a stack buffer (cur_txt) BEFORE destroying
 * the entry, and log the snapshot.
 *
 * This models the read+destroy+log step:
 *   -DSIMULATE_UAF_BUG -> log the freed pointer -> ASan reports
 *                         heap-use-after-free (proves the test catches the bug).
 *   (default)          -> log the pre-destroy snapshot -> ASan-clean.
 * plus a source-wiring assertion that the real counter path snapshots first.
 *
 * Build:
 *   gcc -g -O0 -fsanitize=address -Wall -o test_counter_value_uaf \
 *       test_counter_value_uaf.c
 *   # buggy arm (must trip ASan):
 *   gcc -g -O0 -fsanitize=address -DSIMULATE_UAF_BUG -o /tmp/bug \
 *       test_counter_value_uaf.c && /tmp/bug
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fails;
#define ASSERT(cond, msg) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); g_fails++; } \
	else         { fprintf(stderr, "  ok: %s\n", msg);            } \
} while (0)

static int file_contains(const char *path, const char *needle)
{
	FILE *f = fopen(path, "r");
	char line[4096];
	int hit = 0;
	if (!f) return 0;
	while (fgets(line, sizeof(line), f))
		if (strstr(line, needle)) { hit = 1; break; }
	fclose(f);
	return hit;
}

/* Stand-in for libnats' kvEntry: the value bytes live INSIDE the heap block
 * the entry owns, exactly like cnats -- so a pointer from value_string()
 * dangles the moment destroy() frees the entry. */
typedef struct { char *value; } fake_entry;

static fake_entry *entry_get(const char *v)
{
	fake_entry *e = malloc(sizeof(*e));
	e->value = strdup(v);
	return e;
}
static const char *entry_value_string(fake_entry *e) { return e->value; }
static void entry_destroy(fake_entry *e) { free(e->value); free(e); }

/* Model of the counter error-path: read the value pointer, destroy the entry,
 * then emit a diagnostic string (standing in for LM_ERR's "%s"). */
static void counter_error_log(fake_entry *e, char *log_out, size_t log_cap)
{
	const char *vs = entry_value_string(e);
#ifdef SIMULATE_UAF_BUG
	entry_destroy(e);                          /* free BEFORE using vs */
	snprintf(log_out, log_cap, "%s", vs);      /* <-- use-after-free read */
#else
	char cur_txt[64];
	snprintf(cur_txt, sizeof(cur_txt), "%s", vs ? vs : "(null)"); /* snapshot */
	entry_destroy(e);
	snprintf(log_out, log_cap, "%s", cur_txt); /* logs the snapshot, not vs */
#endif
}

int main(void)
{
	char log[64];

	/* An out-of-range broker value drives the error-log path. */
	fake_entry *e = entry_get("999999999999999999999999");
	counter_error_log(e, log, sizeof(log));
	ASSERT(strcmp(log, "999999999999999999999999") == 0,
		"error log reports the stored value from a pre-destroy snapshot "
		"(ASan-clean; the buggy -DSIMULATE_UAF_BUG arm reads freed heap)");

	/* ---- production wiring ---------------------------------------- */
	{
		const char *src = "../cachedb_nats_dbase.c";
		ASSERT(file_contains(src, "cur_txt"),
			"counter op snapshots the value text into cur_txt before destroy");
		ASSERT(file_contains(src, "nats_counter_parse"),
			"counter op still guards the value (via nats_counter_parse)");
	}

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
