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
 * cachedb_nats_dbase.h — KV Store Parameters and Buffer Constants
 *
 * Module:  cachedb_nats
 *
 * Declares the module-level KV bucket configuration parameters (set via
 * opensips.cfg modparam) and buffer size / retry constants used by the
 * cachedb_nats_dbase.c implementation.
 *
 * Key constants:
 *   NATS_KEY_BUF_SIZE   — maximum key buffer for null-termination
 *   NATS_VAL_BUF_SIZE   — maximum value buffer for null-termination
 *   NATS_CAS_RETRIES    — CAS retry limit for atomic counters
 *
 * Key externs:
 *   kv_bucket, kv_replicas, kv_history, kv_ttl — bucket parameters
 */

#ifndef CACHEDB_NATS_DBASE_H
#define CACHEDB_NATS_DBASE_H

#include "cachedb_nats.h"

/*
 * Module parameters for KV bucket configuration.
 * Defined in cachedb_nats.c, set via modparam in opensips.cfg.
 * These values are used when creating a new KV bucket (existing
 * buckets retain their server-side configuration).
 */

/* KV bucket name.  Default: "opensips".
 * Must be a valid NATS subject token (no dots, colons, or spaces). */
extern char *kv_bucket;

/* JetStream replication factor for the KV bucket.
 * Default: 3 (matches the 3-node cluster).  Minimum: 1. */
extern int   kv_replicas;

/* Number of historical revisions to retain per key.
 * Default: 1 (current value only).  Higher values enable
 * nats_kv_history() to retrieve past revisions. */
extern int   kv_history;

/* Bucket-wide TTL in seconds.  Default: 0 (no expiration).
 * When set, all keys in the bucket expire after this duration
 * unless updated. */
extern int   kv_ttl;

/* Maximum buffer size in bytes for null-terminating KV keys.
 * OpenSIPS str values are not null-terminated; the dbase layer
 * copies keys into a stack buffer of this size before passing
 * to nats.c (which requires C strings). */
#define NATS_KEY_BUF_SIZE   512

/* Maximum buffer size in bytes for null-terminating KV values.
 * Same rationale as NATS_KEY_BUF_SIZE.  Values exceeding this
 * size are heap-allocated instead. */
#define NATS_VAL_BUF_SIZE   4096

/* Maximum number of compare-and-swap retries for atomic counter
 * operations (nats_cache_add, nats_cache_sub).  Each retry reads
 * the current value, computes the new value, and attempts a CAS
 * update.  If all retries fail (due to concurrent writers), the
 * operation returns -1. */
#define NATS_CAS_RETRIES    3

#endif /* CACHEDB_NATS_DBASE_H */
