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
 * nats_tls_openssl -- preload selector for the OpenSSL-backed libnats.
 *
 * Purpose
 *   This module declares the operator's intent that the libnats C
 *   client be linked to the OpenSSL TLS backend.  At mod_init it
 *   performs an explicit dlopen("libnats.so.3", RTLD_NOW | RTLD_GLOBAL)
 *   so libnats's symbols enter the global dynamic-linker namespace
 *   before any of the NATS user modules (event_nats, cachedb_nats,
 *   nats_consumer) are loaded.  When those user modules subsequently
 *   resolve their DT_NEEDED libnats.so.3 reference, the dynamic
 *   linker reuses the already-loaded copy by SONAME match.
 *
 * Why a wrapper module instead of LD_LIBRARY_PATH
 *   Operator UX matches the existing SIP-side TLS backend selection
 *   in tls_mgm/tls_openssl/tls_wolfssl: the choice lives in
 *   opensips.cfg as a `loadmodule` line, grep-able, audit-friendly,
 *   and validated at config-parse time rather than via env-var
 *   inspection.  The wrapper also enforces mutual exclusion with
 *   the nats_tls_wolfssl wrapper and fails loudly if both are
 *   loaded.
 *
 * Load order
 *   This module must be loaded before any NATS user module so that
 *   the dlopen runs before those modules resolve libnats symbols.
 *   The NATS user modules declare a soft `module_dependency_t` on
 *   either this module or nats_tls_wolfssl; the operator's
 *   `loadmodule` order in opensips.cfg is what actually drives the
 *   load sequence.
 */

#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>

#include "../../sr_module.h"
#include "../../dprint.h"

/* Path of the libnats this wrapper loaded.  Populated by mod_load;
 * read by mod_init for the diagnostic log.  When the env var
 * NATS_TLS_LIBNATS_PATH is set, that path wins.  Otherwise the
 * default name list (libnats.so.3.13 → .3.12 → ... → libnats.so)
 * is tried; the first one that dlopens wins.
 *
 * Why an env var rather than a modparam: modparams are parsed
 * AFTER mod_load runs, but mod_load is exactly the point at which
 * we need to dlopen libnats -- it fires before subsequent
 * loadmodule directives, so the NATS user modules' DT_NEEDED
 * resolution sees our dlopen.  A modparam wouldn't be readable
 * at mod_load time. */
static const char *nats_resolved_path = NULL;

/* dlopen handle.  Kept so mod_destroy can dlclose() cleanly on
 * shutdown.  The libnats globals (allocator, signal mask, lib
 * lifecycle counter) are owned by whichever NATS user module
 * called nats_Open() first; dlclose here only drops the refcount
 * that this wrapper added at mod_init. */
static void *_handle = NULL;

static int mod_load(void);
static int mod_init(void);
static void mod_destroy(void);

struct module_exports exports = {
	"nats_tls_openssl",  /* module name */
	MOD_TYPE_DEFAULT,    /* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,     /* dlopen flags for THIS module (libnats's
	                      * symbols get their own RTLD_GLOBAL via
	                      * the explicit dlopen in mod_load) */
	mod_load,            /* load function -- runs immediately after
	                      * dlopen of this wrapper, BEFORE the next
	                      * loadmodule directive is processed.  This
	                      * is the only place where dlopen of
	                      * libnats happens early enough that user
	                      * modules' DT_NEEDED resolution sees it. */
	NULL,                /* OpenSIPS module dependencies */
	0,                   /* exported commands */
	0,                   /* exported async commands */
	0,                   /* module parameters */
	0,                   /* exported statistics */
	0,                   /* exported MI functions */
	0,                   /* exported pseudo-variables */
	0,                   /* exported transformations */
	0,                   /* extra processes */
	0,                   /* module pre-initialization function */
	mod_init,            /* module initialization function */
	0,                   /* response function */
	mod_destroy,         /* destroy function */
	0,                   /* per-child init function */
	0                    /* reload confirm function */
};

/*
 * Default libnats names tried in order when the operator does not
 * set the `libnats_path` modparam.  libnats's upstream packaging
 * uses MAJOR.MINOR as its SONAME (`libnats.so.3.13`, `.3.12`, etc.
 * rather than `libnats.so.3`), so the bare major SONAME does not
 * resolve against most installs; we therefore try a window of
 * recent minor versions before falling back to the dev-package
 * symlink.  Operators on a libnats outside this window can
 * override via the `libnats_path` modparam.
 *
 * The list is short and the dlopen attempts that miss fail fast
 * (no disk I/O once ld.so determines the file is absent), so the
 * startup-time cost is sub-millisecond even when the last entry
 * is the one that resolves.
 */
static const char *default_libnats_names[] = {
	"libnats.so.3.13",
	"libnats.so.3.12",
	"libnats.so.3.11",
	"libnats.so.3.10",
	"libnats.so.3.9",
	"libnats.so.3.8",
	"libnats.so.3.7",
	"libnats.so.3",      /* hypothetical post-realign SONAME */
	"libnats.so",        /* dev-package symlink */
	NULL
};

/* mod_load: pre-load libnats so subsequent loadmodule directives
 * (event_nats, cachedb_nats, nats_consumer) resolve their
 * DT_NEEDED libnats.so against the SO we just dlopen-ed.  This
 * fires immediately after the wrapper's own dlopen, BEFORE the
 * next loadmodule line in opensips.cfg runs. */
static int mod_load(void)
{
	const char *env = getenv("NATS_TLS_LIBNATS_PATH");
	void *sentinel;

	/* RTLD_NOW: resolve all symbols up-front so a missing function
	 *           surfaces at module-load time, not at first call.
	 * RTLD_GLOBAL: put libnats's symbols in the global dynamic-
	 *           linker namespace so subsequent module loads
	 *           reuse this copy by SONAME match. */
	if (env && *env) {
		_handle = dlopen(env, RTLD_NOW | RTLD_GLOBAL);
		if (!_handle) {
			LM_ERR("nats_tls_openssl: dlopen('%s') from "
			       "$NATS_TLS_LIBNATS_PATH failed: %s\n",
			       env, dlerror());
			return -1;
		}
		nats_resolved_path = env;
	} else {
		const char **np;
		for (np = default_libnats_names; *np; np++) {
			_handle = dlopen(*np, RTLD_NOW | RTLD_GLOBAL);
			if (_handle) {
				nats_resolved_path = *np;
				break;
			}
		}
		if (!_handle) {
			LM_ERR("nats_tls_openssl: no libnats build found via "
			       "default SONAME search (tried minor versions "
			       "3.7 through 3.13, plus libnats.so.3 and "
			       "libnats.so).  Install libnats from a distro "
			       "package or set $NATS_TLS_LIBNATS_PATH to "
			       "the exact SONAME / file path.\n");
			return -1;
		}
	}

	/* Sentinel check: confirm the loaded SO exports the libnats
	 * API surface.  Catches a packaging mistake where the path
	 * resolves to a stub or a non-libnats SO that happens to
	 * share the SONAME. */
	sentinel = dlsym(_handle, "natsConnection_Connect");
	if (!sentinel) {
		LM_ERR("nats_tls_openssl: sanity-check failed -- loaded "
		       "'%s' does not export natsConnection_Connect (%s)\n",
		       nats_resolved_path,
		       dlerror() ? dlerror() : "no error string");
		dlclose(_handle);
		_handle = NULL;
		return -1;
	}

	LM_INFO("nats_tls_openssl: loaded '%s' (TLS backend = OpenSSL)\n",
	        nats_resolved_path);
	return 0;
}

static int mod_init(void)
{
	/* Mutual exclusion: only one libnats variant can be live in a
	 * single process.  This check fires at the second wrapper's
	 * mod_init; if both were loaded, OpenSIPS aborts here before
	 * any traffic flows.  (Both wrappers' mod_load already ran by
	 * this point, so the damage of double-dlopen is already
	 * present in memory, but no real RPC has happened yet.) */
	if (module_loaded("nats_tls_wolfssl")) {
		LM_ERR("nats_tls_openssl: nats_tls_wolfssl is also loaded; "
		       "load exactly one TLS-backend wrapper module\n");
		return -1;
	}
	return 0;
}

static void mod_destroy(void)
{
	if (_handle) {
		dlclose(_handle);
		_handle = NULL;
	}
}
