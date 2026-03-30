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

#ifndef CACHEDB_NATS_DBASE_H
#define CACHEDB_NATS_DBASE_H

#include "cachedb_nats.h"

/* module parameters (defined in cachedb_nats.c) */
extern char *kv_bucket;
extern int   kv_replicas;
extern int   kv_history;
extern int   kv_ttl;

/* maximum key/value buffer sizes for null-termination */
#define NATS_KEY_BUF_SIZE   512
#define NATS_VAL_BUF_SIZE   4096

/* CAS retry limit for atomic counter operations */
#define NATS_CAS_RETRIES    3

#endif /* CACHEDB_NATS_DBASE_H */
