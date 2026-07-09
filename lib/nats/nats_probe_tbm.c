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
 * Compile-only feature probe: does this libnats know
 * kvConfig.AllowMsgTTLBelowMarker (fork branch
 * feature/kv-allow-msg-ttl-below-marker)?
 *
 * Makefile.nats compiles this file with -fsyntax-only; success defines
 * LIBNATS_HAS_TTL_BELOW_MARKER for the tree.  A checked-in source file is
 * used instead of inline C in $(shell ...) because a literal '#' inside a
 * make function call breaks make 4.2 (the Main CI runner) -- see the
 * OpenSIPS CI make gotcha.
 *
 * Never linked into anything.
 */

#include <nats/nats.h>

static kvConfig _probe_cfg;
static char _probe_field = (char)sizeof(_probe_cfg.AllowMsgTTLBelowMarker);

/* silence -Wunused warnings under -fsyntax-only pedantry */
char *nats_probe_tbm_refs[] = { (char *)&_probe_cfg, &_probe_field };
