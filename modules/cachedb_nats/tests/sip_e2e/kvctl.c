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
 *
 * kvctl -- minimal KV bucket control for the sip_e2e suite.
 *
 * The nats CLI on this host (0.1.6) predates per-message TTL, so a bucket it
 * creates lacks AllowMsgTTL and the module's capability probe would latch
 * TTL off -- masking exactly the behavior the TTL e2e cases exist to prove.
 * This tool creates buckets the way nats_pool_get_kv does (History +
 * kvConfig.LimitMarkerTTL, nats.c PR #1000), and deletes them stream-level
 * (no lingering tombstones).
 *
 *   kvctl mk <url> <bucket> <history> <marker_ttl_s>
 *       marker_ttl_s > 0: TTL-capable bucket (AllowMsgTTL via LimitMarkerTTL)
 *       marker_ttl_s = 0: plain bucket (models a legacy/pre-existing bucket)
 *   kvctl rm <url> <bucket>
 *   kvctl ls <url> <bucket>
 *       one LIVE key per line -- kvStore_Keys through a marker-aware libnats,
 *       because `nats kv ls` on this host's 0.1.6 CLI predates delete markers
 *       and lists a marker'd (already-expired) key as live.
 *
 * Build: see Makefile (links the >=PR-#1000 libnats).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <nats/nats.h>

static int usage(void)
{
	fprintf(stderr, "usage: kvctl mk <url> <bucket> <history> <marker_ttl_s>\n"
	                "       kvctl rm <url> <bucket>\n");
	return 2;
}

int main(int argc, char **argv)
{
	natsConnection *nc = NULL;
	jsCtx *js = NULL;
	natsStatus s;
	int rc = 1;

	if (argc < 4)
		return usage();

	s = natsConnection_ConnectTo(&nc, argv[2]);
	if (s != NATS_OK) {
		fprintf(stderr, "kvctl: connect %s: %s\n", argv[2],
			natsStatus_GetText(s));
		return 1;
	}
	if (natsConnection_JetStream(&js, nc, NULL) != NATS_OK) {
		fprintf(stderr, "kvctl: no JetStream context\n");
		goto out;
	}

	if (strcmp(argv[1], "mk") == 0 && argc == 6) {
		kvConfig cfg;
		kvStore *kv = NULL;
		long hist = strtol(argv[4], NULL, 10);
		long marker_s = strtol(argv[5], NULL, 10);

		kvConfig_Init(&cfg);
		cfg.Bucket = argv[3];
		cfg.History = hist > 0 ? (int)hist : 1;
		cfg.Replicas = 1;
		if (marker_s > 0)
			cfg.LimitMarkerTTL = marker_s * 1000000000LL;

		s = js_CreateKeyValue(&kv, js, &cfg);
		if (s != NATS_OK) {
			fprintf(stderr, "kvctl: create %s: %s\n", argv[3],
				natsStatus_GetText(s));
			goto out;
		}
		kvStore_Destroy(kv);
		rc = 0;
	} else if (strcmp(argv[1], "ls") == 0 && argc == 4) {
		kvStore *kv = NULL;
		kvKeysList kl;
		int i;

		s = js_KeyValue(&kv, js, argv[3]);
		if (s != NATS_OK) {
			rc = 0;              /* absent bucket = no live keys */
			goto out;
		}
		memset(&kl, 0, sizeof(kl));
		s = kvStore_Keys(&kl, kv, NULL);
		if (s == NATS_OK) {
			for (i = 0; i < kl.Count; i++)
				if (kl.Keys[i])
					printf("%s\n", kl.Keys[i]);
			kvKeysList_Destroy(&kl);
			rc = 0;
		} else {
			rc = (s == NATS_NOT_FOUND) ? 0 : 1;   /* empty bucket = ok */
		}
		kvStore_Destroy(kv);
	} else if (strcmp(argv[1], "rm") == 0 && argc == 4) {
		char stream[256];
		jsErrCode je = 0;
		snprintf(stream, sizeof(stream), "KV_%s", argv[3]);
		s = js_DeleteStream(js, stream, NULL, &je);
		/* absent stream is success for a cleanup tool */
		rc = (s == NATS_OK || s == NATS_NOT_FOUND || je == 10059) ? 0 : 1;
		if (rc)
			fprintf(stderr, "kvctl: delete %s: %s (jerr=%d)\n", stream,
				natsStatus_GetText(s), je);
	} else {
		rc = usage();
	}

out:
	if (js)
		jsCtx_Destroy(js);
	natsConnection_Destroy(nc);
	nats_Close();
	return rc;
}
