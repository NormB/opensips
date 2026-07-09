/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * This file is part of opensips, a free SIP server.
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
 * test_shim.h -- drop-in replacement for shm_mem.h + rw_locking.h + dprint.h
 * so the registry and parser can be compiled and run in a plain process
 * unit test.  Included only when -DTEST_SHIM is on.
 */

#ifndef NATS_CONSUMER_TEST_SHIM_H
#define NATS_CONSUMER_TEST_SHIM_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

/* ── allocator ───────────────────────────────────────────────── */

void *test_shm_malloc(size_t n);
void *test_shm_realloc(void *p, size_t n);
void  test_shm_free(void *p);

#define shm_malloc(n)     test_shm_malloc(n)
#define shm_malloc_func   test_shm_malloc_func
#define shm_realloc(p,n)  test_shm_realloc((p),(n))
#define shm_free(p)       test_shm_free(p)

/* pkg_* are aliased to the same plain malloc in tests. */
#define pkg_malloc(n)     test_shm_malloc(n)
#define pkg_realloc(p,n)  test_shm_realloc((p),(n))
#define pkg_free(p)       test_shm_free(p)

/* ── dprint ──────────────────────────────────────────────────── */

#define LM_ERR(fmt, ...)  fprintf(stderr, "ERR:  " fmt, ##__VA_ARGS__)
#define LM_WARN(fmt, ...) fprintf(stderr, "WARN: " fmt, ##__VA_ARGS__)
#define LM_INFO(fmt, ...) fprintf(stderr, "INFO: " fmt, ##__VA_ARGS__)
#define LM_DBG(fmt, ...)  do {} while (0)
#define LM_NOTICE(fmt, ...) fprintf(stderr, "NOTE: " fmt, ##__VA_ARGS__)
#define LM_CRIT(fmt, ...) fprintf(stderr, "CRIT: " fmt, ##__VA_ARGS__)
#define LM_ALERT(fmt, ...) fprintf(stderr, "ALRT: " fmt, ##__VA_ARGS__)

/* ── rw_lock ─────────────────────────────────────────────────── */

typedef struct rw_lock_t {
	pthread_rwlock_t rw;
} rw_lock_t;

rw_lock_t *test_lock_init_rw(void);
void       test_lock_destroy_rw(rw_lock_t *l);

#define lock_init_rw()       test_lock_init_rw()
#define lock_destroy_rw(l)   test_lock_destroy_rw(l)

#define lock_start_read(l)   pthread_rwlock_rdlock(&(l)->rw)
#define lock_stop_read(l)    pthread_rwlock_unlock(&(l)->rw)
#define lock_start_write(l)  pthread_rwlock_wrlock(&(l)->rw)
#define lock_stop_write(l)   pthread_rwlock_unlock(&(l)->rw)

/* ── silence the core str.h include that pulls in lib/str2const.h ── */
/* We still need str.h -- it's a plain header with no core dep. */

/* ── nats_ring fakes ─────────────────────────────────────────── */
/* The registry allocates/frees each handle's SHM ring through
 * nats_ring_create()/nats_ring_destroy().  Unit tests link these
 * counting fakes instead of ../nats_ring.c (the real ring needs
 * eventfd + SHM atomics), so ordering contracts like "a rejected
 * duplicate bind must not allocate a ring" are observable. */

extern int test_ring_creates;    /* nats_ring_create() calls  */
extern int test_ring_destroys;   /* nats_ring_destroy() calls */

#endif /* NATS_CONSUMER_TEST_SHIM_H */
