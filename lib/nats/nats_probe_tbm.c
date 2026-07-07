/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
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
