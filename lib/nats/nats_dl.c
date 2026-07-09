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
 * nats_dl.c -- runtime dlopen of libnats + dlsym population of the
 * function-pointer table declared in nats_dl.h.  See that header
 * for the architectural rationale.
 */

#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>

#include "nats_dl.h"
#include "../../dprint.h"

/*
 * Global function-pointer table.  Defined here, declared extern in
 * nats_dl.h, populated by nats_dl_load().
 */
nats_dl_funcs_t nats_dl;

/*
 * dlopen handle and the path that was successfully loaded.  Both
 * are owned by this translation unit; nats_dl_path() returns a
 * borrowed pointer to _path.
 */
static void       *_handle = NULL;
static const char *_path   = NULL;

/*
 * try_dlopen -- dlopen with RTLD_NOW | RTLD_GLOBAL.
 *
 * RTLD_NOW: resolve every symbol up-front so a missing function
 *           surfaces here instead of at first call from production
 *           code paths.
 * RTLD_GLOBAL: place libnats's symbols in the global dynamic-linker
 *           namespace.  Currently unused (no other DT_NEEDED in this
 *           tree resolves against libnats), but cheap and forwards-
 *           compatible if a future module wants to mix dlopen +
 *           DT_NEEDED.
 */
static void *try_dlopen(const char *path)
{
	return dlopen(path, RTLD_NOW | RTLD_GLOBAL);
}

/*
 * Default SONAME tried when no explicit path or env override is set.
 * The dev-package symlink (libnats.so) is what every distro's
 * `libnats-dev` / `libnats-devel` ships, and what the build's
 * pkg-config probe found at compile time.  ld.so's standard search
 * (LD_LIBRARY_PATH, ldconfig cache, default /lib + /usr/lib) finds
 * whichever libnats install the operator has activated -- exactly
 * the same selection mechanism every other shared lib uses.
 *
 * Operators with multiple libnats installs (e.g. an openssl-linked
 * one and a wolfssl-linked one side-by-side) point at the desired
 * variant via $NATS_DL_LIBNATS_PATH.  Lib/nats deliberately does
 * NOT bake in install-prefix conventions like /opt/libnats-wolfssl/
 * -- those are deployment policy, not library policy.
 */
#define NATS_DL_DEFAULT_SONAME "libnats.so"

int nats_dl_load(const char *libnats_path)
{
	const char *env_override;

	if (_handle)
		return 0;  /* idempotent */

	/*
	 * Explicit path argument wins (caller knows exactly what they
	 * want).  No env var or default considered.
	 */
	if (libnats_path && *libnats_path) {
		_handle = try_dlopen(libnats_path);
		if (!_handle) {
			LM_ERR("nats_dl: dlopen('%s') failed: %s\n",
			       libnats_path, dlerror());
			return -1;
		}
		_path = libnats_path;
		goto loaded;
	}

	/*
	 * Env-var override is the operator's escape hatch when the
	 * default SONAME isn't on ld.so's search path (custom install
	 * prefix, side-by-side openssl + wolfssl libnats variants,
	 * etc.).  If set and the path fails, fall back to the default
	 * SONAME with an LM_WARN -- the operator gets a loud signal
	 * about the bad env var instead of a silent retry.
	 */
	env_override = getenv("NATS_DL_LIBNATS_PATH");
	if (env_override && *env_override) {
		_handle = try_dlopen(env_override);
		if (_handle) {
			_path = env_override;
			goto loaded;
		}
		LM_WARN("nats_dl: $NATS_DL_LIBNATS_PATH='%s' dlopen failed "
		        "(%s); falling back to default SONAME '%s'\n",
		        env_override, dlerror(), NATS_DL_DEFAULT_SONAME);
	}

	_handle = try_dlopen(NATS_DL_DEFAULT_SONAME);
	if (!_handle) {
		LM_ERR("nats_dl: dlopen('%s') failed: %s.  Install libnats "
		       "(libnats-dev / libnats-devel) so the dev-package "
		       "symlink is on ld.so's search path, or set "
		       "$NATS_DL_LIBNATS_PATH to an explicit libnats path.\n",
		       NATS_DL_DEFAULT_SONAME, dlerror());
		return -1;
	}
	_path = NATS_DL_DEFAULT_SONAME;

loaded:

	/*
	 * Populate every function pointer.  The X-macro expansion below
	 * matches the one in nats_dl.h; if a libnats function we use is
	 * absent from the loaded SO (wrong libnats version, build option
	 * removed, etc.), this loop fails closed -- the table is left
	 * with NULL entries that would crash on first call -- so we
	 * dlclose and return -1 to keep the call sites safe.
	 */
	memset(&nats_dl, 0, sizeof(nats_dl));
#define NATS_DL_FN(sym) \
	do { \
		nats_dl.sym = (__typeof__(nats_dl.sym)) dlsym(_handle, #sym); \
		if (!nats_dl.sym) { \
			const char *_dlerr = dlerror(); \
			(void)_dlerr; /* LM_ERR is a no-op in unit builds */ \
			LM_ERR("nats_dl: '%s' missing required libnats " \
			       "symbol '%s' (%s)\n", _path, #sym, \
			       _dlerr ? _dlerr : "no error string"); \
			dlclose(_handle); \
			_handle = NULL; \
			_path   = NULL; \
			memset(&nats_dl, 0, sizeof(nats_dl)); \
			return -1; \
		} \
	} while (0);
#include "nats_dl_table.def"
#undef NATS_DL_FN

	LM_INFO("nats_dl: loaded '%s'; %zu libnats symbols resolved\n",
	        _path, sizeof(nats_dl) / sizeof(void *));
	return 0;
}

void nats_dl_unload(void)
{
	if (_handle) {
		dlclose(_handle);
		_handle = NULL;
		_path   = NULL;
		memset(&nats_dl, 0, sizeof(nats_dl));
	}
}

int nats_dl_is_loaded(void)
{
	return _handle != NULL;
}

const char *nats_dl_path(void)
{
	return _path;
}
