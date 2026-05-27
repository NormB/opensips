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
 * nats_rpc_subject.h -- reply-inbox subject grammar for the
 * consumer-process-routed async nats_request transport.
 *
 *     "<prefix>.<slot_idx>.<generation>"
 *
 * The trailing <slot_idx>.<generation> pair is how the consumer's
 * libnats reply callback correlates a reply to its SHM slot without a
 * hash table.  The <generation> guards against a late reply landing on
 * a slot that has since been freed and re-claimed by a *different*
 * request: the reply echoes the generation captured at publish time,
 * and on_inbox_reply drops the reply when the slot's current generation
 * no longer matches.  Without this, a responder slower than the request
 * timeout could have its reply delivered to whoever re-claimed the slot
 * (a cross-call data leak).
 *
 * Both functions are pure (no libnats / OpenSIPS dependencies) so they
 * can be unit-tested standalone -- see tests/test_rpc_subject.c.
 */

#ifndef NATS_RPC_SUBJECT_H
#define NATS_RPC_SUBJECT_H

#include <stdint.h>
#include <stddef.h>

/*
 * Build "<prefix>.<slot>.<gen>" into out[0..out_sz).  Returns the
 * written length (excluding the NUL) on success, or -1 on overflow or
 * bad arguments.
 */
int nats_rpc_subject_build(char *out, size_t out_sz,
                           const char *prefix, uint32_t slot, uint32_t gen);

/*
 * Parse the trailing ".<slot>.<gen>" off a reply subject.  The prefix
 * itself contains dots and is NOT validated -- only the final two
 * dot-separated decimal segments are read.  Returns 0 with *slot and
 * *gen populated on success, -1 on malformed input.
 */
int nats_rpc_subject_parse(const char *subject, int len,
                           uint32_t *slot, uint32_t *gen);

#endif /* NATS_RPC_SUBJECT_H */
