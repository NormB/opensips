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
 * Default search list when nats_dl_load(NULL) is called.  libnats
 * upstream packaging uses MAJOR.MINOR as the SONAME (libnats.so.3.13,
 * .3.12, ...) instead of bare libnats.so.3, so we walk a window of
 * recent minor versions before falling back to the dev-package
 * symlink.  Operators on a libnats outside this window can pass an
 * explicit path to nats_dl_load().
 *
 * The list is short, dlopen failure on a missing path is sub-
 * millisecond (ld.so determines absence without disk I/O after the
 * first miss), and only the first hit dlopens the SO -- so the
 * worst-case startup-time cost is dominated by the one successful
 * load.
 */
static const char *default_libnats_search[] = {
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

/*
 * try_dlopen -- dlopen with RTLD_NOW | RTLD_GLOBAL.
 *
 * RTLD_NOW: resolve every symbol up-front so a missing function
 *           surfaces here instead of at first call from production
 *           code paths.
 * RTLD_GLOBAL: place libnats's symbols in the global dynamic-linker
 *           namespace.  Currently unused (no other DT_NEEDED is
 *           expected to resolve against libnats post-Phase-1), but
 *           cheap and forwards-compatible if a future module wants
 *           to mix dlopen + DT_NEEDED.
 */
static void *try_dlopen(const char *path)
{
	return dlopen(path, RTLD_NOW | RTLD_GLOBAL);
}

int nats_dl_load(const char *libnats_path)
{
	if (_handle)
		return 0;  /* idempotent */

	if (libnats_path && *libnats_path) {
		_handle = try_dlopen(libnats_path);
		if (!_handle) {
			LM_ERR("nats_dl: dlopen('%s') failed: %s\n",
			       libnats_path, dlerror());
			return -1;
		}
		_path = libnats_path;
	} else {
		const char **np;
		for (np = default_libnats_search; *np; np++) {
			_handle = try_dlopen(*np);
			if (_handle) {
				_path = *np;
				break;
			}
		}
		if (!_handle) {
			LM_ERR("nats_dl: no libnats build found via default "
			       "SONAME search (tried %s through %s).  Install "
			       "libnats from a distro package or pass an "
			       "explicit path to nats_dl_load().\n",
			       default_libnats_search[0],
			       default_libnats_search[
			           sizeof(default_libnats_search) /
			           sizeof(default_libnats_search[0]) - 2]);
			return -1;
		}
	}

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
			LM_ERR("nats_dl: '%s' missing required libnats " \
			       "symbol '%s' (%s)\n", _path, #sym, \
			       dlerror() ? dlerror() : "no error string"); \
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
