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
#include <string.h>

#include "../../sr_module.h"
#include "../../dprint.h"

/* Optional override of the libnats path / SONAME.  Defaults to
 * "libnats.so.3", which the dynamic linker resolves against the
 * standard search path (ld.so.cache + /lib + /usr/lib + LOCALBASE).
 * Distros that ship libnats in a non-standard directory or that
 * version-suffix the SONAME differently can point at the exact
 * file.  Must not contain a wolfSSL-flavoured libnats path -- the
 * sentinel check below does not validate the TLS backend, only
 * that libnats is loadable. */
static char *nats_libnats_path = NULL;

/* dlopen handle.  Kept so mod_destroy can dlclose() cleanly on
 * shutdown.  The libnats globals (allocator, signal mask, lib
 * lifecycle counter) are owned by whichever NATS user module
 * called nats_Open() first; dlclose here only drops the refcount
 * that this wrapper added at mod_init. */
static void *_handle = NULL;

static int mod_init(void);
static void mod_destroy(void);

static const param_export_t params[] = {
	{"libnats_path", STR_PARAM, &nats_libnats_path},
	{0, 0, 0}
};

struct module_exports exports = {
	"nats_tls_openssl",  /* module name */
	MOD_TYPE_DEFAULT,    /* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,     /* dlopen flags for THIS module (libnats's
	                      * symbols get their own RTLD_GLOBAL via
	                      * the explicit dlopen below) */
	0,                   /* load function */
	NULL,                /* OpenSIPS module dependencies */
	0,                   /* exported commands */
	0,                   /* exported async commands */
	params,              /* module parameters */
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
 * uses MAJOR.MINOR as its SONAME (`libnats.so.3.13` rather than
 * `libnats.so.3`), so the bare major SONAME would never resolve;
 * we therefore try the most-specific name first and fall back
 * through coarser variants.  Operators on non-3.13 libnats
 * versions can override via the `libnats_path` modparam.
 */
static const char *default_libnats_names[] = {
	"libnats.so.3.13",   /* current upstream SONAME */
	"libnats.so.3",      /* hypothetical post-realign SONAME */
	"libnats.so",        /* dev-package symlink */
	NULL
};

static int mod_init(void)
{
	void *sentinel;

	LM_INFO("nats_tls_openssl: initializing\n");

	/* Mutual exclusion: only one libnats variant can be live in a
	 * single process.  Loading both wrapper modules would double-
	 * dlopen libnats and (if the two prefixes are configured to
	 * point at different libnats builds) lead to undefined
	 * behaviour at the first global-state access. */
	if (module_loaded("nats_tls_wolfssl")) {
		LM_ERR("nats_tls_openssl: nats_tls_wolfssl is also loaded; "
		       "load exactly one TLS-backend wrapper module\n");
		return -1;
	}

	/* RTLD_NOW: resolve all symbols up-front so we know now if
	 *           the libnats build is incomplete (rather than
	 *           failing on the first call site).
	 * RTLD_GLOBAL: put libnats's symbols in the global namespace
	 *           so the NATS user modules' DT_NEEDED resolution
	 *           reuses this load by SONAME match. */
	if (nats_libnats_path && *nats_libnats_path) {
		_handle = dlopen(nats_libnats_path, RTLD_NOW | RTLD_GLOBAL);
		if (!_handle) {
			LM_ERR("nats_tls_openssl: dlopen('%s') failed: %s\n",
			       nats_libnats_path, dlerror());
			return -1;
		}
	} else {
		/* Walk default name list until one resolves. */
		const char **np;
		for (np = default_libnats_names; *np; np++) {
			_handle = dlopen(*np, RTLD_NOW | RTLD_GLOBAL);
			if (_handle) {
				nats_libnats_path = (char *)*np;
				break;
			}
		}
		if (!_handle) {
			LM_ERR("nats_tls_openssl: no libnats build found via "
			       "default SONAME search (tried: libnats.so.3.13, "
			       ".so.3, .so).  Install libnats from a distro "
			       "package or set the libnats_path modparam.\n");
			return -1;
		}
	}

	/* Sentinel check: confirm the loaded SO actually exports the
	 * libnats API surface.  Catches a packaging mistake where the
	 * configured path points at a stub or a non-libnats SO that
	 * happens to share the SONAME. */
	sentinel = dlsym(_handle, "natsConnection_Connect");
	if (!sentinel) {
		LM_ERR("nats_tls_openssl: sanity-check failed -- loaded "
		       "'%s' does not export natsConnection_Connect (%s)\n",
		       nats_libnats_path,
		       dlerror() ? dlerror() : "no error string");
		dlclose(_handle);
		_handle = NULL;
		return -1;
	}

	LM_INFO("nats_tls_openssl: loaded '%s' (TLS backend = OpenSSL)\n",
	        nats_libnats_path);
	return 0;
}

static void mod_destroy(void)
{
	if (_handle) {
		dlclose(_handle);
		_handle = NULL;
	}
}
