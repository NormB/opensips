/*
 * Copyright (C) 2026 OpenSIPS Solutions
 * Copyright (C) 2026 Norm Brandinger <n.brandinger@gmail.com>
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
 * fake_libnats_version.c -- a stand-in libnats for test_nats_dl's
 * header/runtime version-guard cases.  It exports ONLY
 * nats_GetVersionNumber(), built three ways by tests/Makefile:
 *   fake_libnats_ok.so    -- reports the compiled header's version
 *   fake_libnats_bump.so  -- reports the next minor version (layout drift)
 *   fake_libnats_nover.so -- no nats_GetVersionNumber at all
 */
#include <stdint.h>
#include <nats/nats.h>

#ifndef FAKE_NO_VERSION
uint32_t nats_GetVersionNumber(void)
{
#ifdef FAKE_BUMP_MINOR
	return NATS_VERSION_NUMBER + 0x100;
#else
	return NATS_VERSION_NUMBER;
#endif
}
#else
int fake_libnats_placeholder(void) { return 0; }
#endif
