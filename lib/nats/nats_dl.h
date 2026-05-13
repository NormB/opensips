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
 * nats_dl.h -- libnats function-pointer table.
 *
 * Why this exists
 *   The NATS modules used to link libnats statically via DT_NEEDED.
 *   That made it impossible to choose the libnats variant (openssl-
 *   built vs wolfssl-built) at runtime: the dynamic linker resolved
 *   the dependency at module load time, before any OpenSIPS code
 *   could run.
 *
 *   This table replaces every direct libnats call across lib/nats
 *   and the three NATS user modules (cachedb_nats, event_nats,
 *   nats_consumer) with an indirect call through a function-pointer
 *   table populated at lib/nats init time via dlopen + dlsym.
 *
 *   Result: no .so produced from this tree carries DT_NEEDED for
 *   libnats.so.  lib/nats's runtime backend selector (Phase 2) is
 *   then free to dlopen whichever libnats variant matches the
 *   tls_mgm-configured TLS backend.
 *
 * Single source of truth
 *   The list of every libnats function this codebase calls lives in
 *   nats_dl_table.def.  That file is included twice in the project:
 *   once here (with NATS_DL_FN expanded to declare a struct field)
 *   and once in nats_dl.c (with NATS_DL_FN expanded to dlsym the
 *   matching libnats symbol).  Adding or removing a libnats call in
 *   any NATS source file means: edit nats_dl_table.def, and the
 *   header + loader update automatically.
 *
 * Usage from a NATS source file
 *   #include "nats_dl.h"
 *   ...
 *   natsStatus s = nats_dl.natsConnection_Connect(&nc, opts);
 *
 * Lifecycle
 *   nats_dl_load(libnats_path) is called once per process from
 *   nats_pool_init().  Subsequent calls are no-ops (idempotent).
 *   nats_dl_unload() is called once at lib/nats teardown.
 */

#ifndef LIB_NATS_NATS_DL_H
#define LIB_NATS_NATS_DL_H

#include <nats/nats.h>

/*
 * The function-pointer table.  Each entry has the same signature as
 * the corresponding libnats function, derived via __typeof__ so the
 * declarations stay in sync with libnats's headers automatically.
 *
 * Typical compiler diagnostic: if libnats removes or renames a
 * function this codebase calls, `__typeof__(missing_function)` is
 * an error at THIS header's compile, not at the call site -- which
 * keeps error messages localised to the table.
 */
typedef struct nats_dl_funcs {
#define NATS_DL_FN(sym) __typeof__(sym) *sym;
#include "nats_dl_table.def"
#undef NATS_DL_FN
} nats_dl_funcs_t;

/*
 * Global instance.  Defined in nats_dl.c.  Every NATS source file
 * makes calls of the form `nats_dl.<funcname>(<args>)`; the indirect
 * jump through the populated pointer is one extra branch per call,
 * predicted perfectly by modern CPUs.
 */
extern nats_dl_funcs_t nats_dl;

/*
 * nats_dl_load -- dlopen libnats and populate the table.
 *
 * @libnats_path  full path or SONAME passed to dlopen(); pass NULL
 *                to use the default search list (libnats.so.3.13 ->
 *                .3.12 -> ... -> libnats.so).  When non-NULL, no
 *                fallback is attempted -- if the explicit path
 *                fails, the function returns -1.
 *
 * Returns 0 on success (table populated, every entry non-NULL),
 * -1 on dlopen failure or missing required symbol.  Idempotent:
 * subsequent calls return 0 without re-loading.
 *
 * Caller MUST ensure nats_dl_load returns 0 before any nats_dl.*
 * call.  Calling through a NULL function pointer is undefined
 * behaviour; this loader is the explicit guard.
 */
int  nats_dl_load(const char *libnats_path);

/*
 * nats_dl_unload -- dlclose libnats and zero the table.
 *
 * Called from nats_pool_destroy / mod_destroy paths.  Safe to call
 * when nothing has been loaded (no-op).
 */
void nats_dl_unload(void);

/*
 * nats_dl_is_loaded -- true if dlopen has succeeded.
 *
 * Useful from secondary mod_init paths that need to lazy-load
 * libnats only if it hasn't been loaded yet:
 *   if (!nats_dl_is_loaded()) {
 *       if (nats_dl_load(NULL) < 0) return -1;
 *   }
 */
int  nats_dl_is_loaded(void);

/*
 * nats_dl_path -- the path/SONAME that dlopen succeeded with, or
 * NULL if not loaded.  Pointer is owned by nats_dl; do not free.
 * Useful for diagnostic LM_INFO logs after init.
 */
const char *nats_dl_path(void);

#endif  /* LIB_NATS_NATS_DL_H */
