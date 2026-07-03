/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * This file is part of opensips, a free SIP server.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * test_shim.c -- plain-C stand-ins for SHM and rwlock that let the
 * registry/parser code run in a unit-test harness.
 */

#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <stdio.h>

#include "test_shim.h"

void *test_shm_malloc(size_t n)
{
	return malloc(n);
}

void *test_shm_realloc(void *p, size_t n)
{
	return realloc(p, n);
}

void test_shm_free(void *p)
{
	free(p);
}

/* ── nats_ring counting fakes (see test_shim.h) ─────────────── */

#include <stdint.h>
#include "../nats_ring.h"

int test_ring_creates;
int test_ring_destroys;

/* Weak: tests that link the REAL ../nats_ring.c (test_ring,
 * test_ring_xproc_wakeup) override these; tests that link only the
 * registry get the counting fakes. */
__attribute__((weak)) nats_ring_t *nats_ring_create(uint32_t capacity)
{
	(void)capacity;
	test_ring_creates++;
	/* opaque non-NULL cookie; never dereferenced by the registry */
	return (nats_ring_t *)(uintptr_t)0x51D3;
}

__attribute__((weak)) void nats_ring_destroy(nats_ring_t *r)
{
	(void)r;
	test_ring_destroys++;
}

rw_lock_t *test_lock_init_rw(void)
{
	rw_lock_t *l = (rw_lock_t *)malloc(sizeof(*l));
	if (!l)
		return NULL;
	if (pthread_rwlock_init(&l->rw, NULL) != 0) {
		free(l);
		return NULL;
	}
	return l;
}

void test_lock_destroy_rw(rw_lock_t *l)
{
	if (!l)
		return;
	pthread_rwlock_destroy(&l->rw);
	free(l);
}
