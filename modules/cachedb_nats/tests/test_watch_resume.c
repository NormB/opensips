/*
 * Copyright (C) 2025 Summit-2026 / cachedb_nats contributors
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
 * test_watch_resume.c -- where a rebuilt KV watcher resumes.
 *
 * After a reconnect the watcher must resume right after the last revision
 * it delivered, so changes made while it was disconnected still raise
 * E_NATS_KV_CHANGE, and none is delivered twice.
 */
#include <stdio.h>

#include "../cachedb_nats_watch_resume.h"

static int fails;
#define CHECK(cond, msg) do { if (!(cond)) { printf("  FAIL: %s\n", msg); fails++; } \
	else printf("  ok:   %s\n", msg); } while (0)

int main(void)
{
	struct watch_resume wr = {0};
	uint64_t r;
	int reset;

	printf("first build anchors at the stream's end:\n");
	r = watch_resume_start(&wr, 1, 0, &reset);
	CHECK(r == 1 && !reset, "empty stream: start at revision 1");
	wr.next = 0;
	r = watch_resume_start(&wr, 1, 41, &reset);
	CHECK(r == 42 && !reset, "stream at 41: start at 42 (new changes only)");
	CHECK(wr.next == 42, "anchor kept");

	printf("first build without the stream state:\n");
	{
		struct watch_resume w0 = {0};
		r = watch_resume_start(&w0, 0, 0, &reset);
		CHECK(r == 0 && !reset, "falls back to updates-only");
		CHECK(w0.next == 0, "no anchor invented");
	}

	printf("rebuild resumes after the last delivered revision:\n");
	watch_resume_seen(&wr, 42);
	watch_resume_seen(&wr, 43);
	watch_resume_seen(&wr, 45);
	CHECK(wr.next == 46, "next = last delivered + 1");
	r = watch_resume_start(&wr, 1, 50, &reset);
	CHECK(r == 46 && !reset, "revisions 46..50 written while down are delivered");
	r = watch_resume_start(&wr, 0, 0, &reset);
	CHECK(r == 46 && !reset, "stream state unreadable: still resumes at 46");
	r = watch_resume_start(&wr, 1, 45, &reset);
	CHECK(r == 46 && !reset, "nothing new: nothing delivered twice");

	printf("revisions never move the cursor backwards:\n");
	watch_resume_seen(&wr, 0);
	CHECK(wr.next == 46, "revision 0 ignored");
	watch_resume_seen(&wr, 44);
	CHECK(wr.next == 46, "an older revision does not rewind");

	printf("stream went backwards (bucket deleted and recreated):\n");
	r = watch_resume_start(&wr, 1, 3, &reset);
	CHECK(reset == 1, "reset reported");
	CHECK(r == 4 && wr.next == 4, "restart right after the new stream's end");

	printf("boundaries:\n");
	{
		struct watch_resume wm = {0};
		watch_resume_seen(&wm, UINT64_MAX);
		CHECK(wm.next == UINT64_MAX, "last revision UINT64_MAX does not wrap to 0");
		wm.next = 0;
		r = watch_resume_start(&wm, 1, UINT64_MAX, &reset);
		CHECK(r == UINT64_MAX && !reset, "stream at UINT64_MAX does not wrap to 0");
		wm.next = 0;
		r = watch_resume_start(&wm, 1, UINT64_MAX - 1, &reset);
		CHECK(r == UINT64_MAX, "stream at UINT64_MAX-1: start at UINT64_MAX");
	}

	printf("\n%s (%d failure%s)\n", fails ? "FAILED" : "PASSED", fails, fails == 1 ? "" : "s");
	return fails ? 1 : 0;
}
