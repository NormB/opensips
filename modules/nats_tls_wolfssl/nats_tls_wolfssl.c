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
 * nats_tls_wolfssl -- preload selector for the wolfSSL-backed libnats.
 *
 * See modules/nats_tls_openssl/nats_tls_openssl.c for the full
 * architectural rationale.  This is the symmetric wolfSSL twin:
 * mod_init dlopens a wolfSSL-flavoured libnats build from a
 * deployment-supplied path with RTLD_NOW | RTLD_GLOBAL, ensuring
 * that subsequent NATS user-module DT_NEEDED resolution of
 * libnats.so.3 picks up the wolfSSL build by SONAME match.
 *
 * Deployment expectation
 *   Operators install a wolfSSL-built libnats (typically under
 *   /opt/libnats-wolfssl/) by following the build recipe in
 *   docs/nats-tls-backends.md.  The wolfSSL build links libnats
 *   against wolfSSL's OpenSSL-compatibility layer
 *   (`--enable-opensslextra`), which provides the OpenSSL API
 *   names that libnats's TLS code calls.  wolfSSL ≥ 5.6.0 is
 *   required for the cert-chain walk + hostname-verify surface
 *   libnats uses; older wolfSSL stubs out a couple of cert
 *   helpers that libnats relies on.
 */

#include <dlfcn.h>
#include <string.h>

#include "../../sr_module.h"
#include "../../dprint.h"

/* Path to the wolfSSL-flavoured libnats install.  Default points at
 * the recommended deployment prefix; distros / operators that
 * install elsewhere set this modparam.  Unlike nats_tls_openssl
 * which defaults to a bare SONAME (resolved via ld.so search), this
 * module defaults to an absolute path because wolfSSL-flavoured
 * libnats is not on the system search path on any distro -- it is
 * always a sidecar build. */
static char *nats_libnats_path = "/opt/libnats-wolfssl/lib/libnats.so.3";

static void *_handle = NULL;

static int mod_init(void);
static void mod_destroy(void);

static const param_export_t params[] = {
	{"libnats_path", STR_PARAM, &nats_libnats_path},
	{0, 0, 0}
};

struct module_exports exports = {
	"nats_tls_wolfssl",  /* module name */
	MOD_TYPE_DEFAULT,    /* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,
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

static int mod_init(void)
{
	void *sentinel;

	LM_INFO("nats_tls_wolfssl: initializing\n");

	if (module_loaded("nats_tls_openssl")) {
		LM_ERR("nats_tls_wolfssl: nats_tls_openssl is also loaded; "
		       "load exactly one TLS-backend wrapper module\n");
		return -1;
	}

	if (!nats_libnats_path || !*nats_libnats_path) {
		LM_ERR("nats_tls_wolfssl: libnats_path modparam is empty -- "
		       "wolfSSL-flavoured libnats has no system default; "
		       "set libnats_path to the install location\n");
		return -1;
	}

	_handle = dlopen(nats_libnats_path, RTLD_NOW | RTLD_GLOBAL);
	if (!_handle) {
		LM_ERR("nats_tls_wolfssl: dlopen('%s') failed: %s\n",
		       nats_libnats_path, dlerror());
		return -1;
	}

	sentinel = dlsym(_handle, "natsConnection_Connect");
	if (!sentinel) {
		LM_ERR("nats_tls_wolfssl: sanity-check failed -- loaded "
		       "'%s' does not export natsConnection_Connect (%s)\n",
		       nats_libnats_path,
		       dlerror() ? dlerror() : "no error string");
		dlclose(_handle);
		_handle = NULL;
		return -1;
	}

	LM_INFO("nats_tls_wolfssl: loaded '%s' (TLS backend = wolfSSL)\n",
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
