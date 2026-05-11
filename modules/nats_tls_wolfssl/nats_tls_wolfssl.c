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
#include <stdlib.h>
#include <string.h>

#include "../../sr_module.h"
#include "../../dprint.h"

/* Default path of the wolfSSL-flavoured libnats install.  An env
 * var override (NATS_TLS_LIBNATS_PATH) lets operators with a
 * non-default install (different prefix / different minor version)
 * point at the right file without recompiling this module.
 *
 * Why an env var rather than a modparam: modparams are parsed
 * AFTER mod_load runs, but mod_load is exactly the point at which
 * we need to dlopen libnats -- it fires before subsequent
 * loadmodule directives, so the NATS user modules' DT_NEEDED
 * resolution sees our dlopen. */
static const char *default_libnats_path =
	"/opt/libnats-wolfssl/lib/libnats.so.3.12";

static const char *nats_resolved_path = NULL;
static void *_handle = NULL;

static int mod_load(void);
static int mod_init(void);
static void mod_destroy(void);

struct module_exports exports = {
	"nats_tls_wolfssl",  /* module name */
	MOD_TYPE_DEFAULT,    /* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,
	mod_load,            /* runs before subsequent loadmodule */
	NULL,                /* OpenSIPS module dependencies */
	0,                   /* exported commands */
	0,                   /* exported async commands */
	0,                   /* module parameters (none -- env var) */
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

/* mod_load: pre-load libnats so subsequent loadmodule directives
 * resolve their DT_NEEDED libnats.so against this dlopen.  Fires
 * before the next loadmodule line; cannot read modparams (those
 * haven't been processed yet), so the libnats path is sourced
 * from the env var $NATS_TLS_LIBNATS_PATH or the compile-time
 * default. */
static int mod_load(void)
{
	const char *env = getenv("NATS_TLS_LIBNATS_PATH");
	void *sentinel;

	nats_resolved_path = (env && *env) ? env : default_libnats_path;

	_handle = dlopen(nats_resolved_path, RTLD_NOW | RTLD_GLOBAL);
	if (!_handle) {
		LM_ERR("nats_tls_wolfssl: dlopen('%s') failed: %s\n",
		       nats_resolved_path, dlerror());
		return -1;
	}

	sentinel = dlsym(_handle, "natsConnection_Connect");
	if (!sentinel) {
		LM_ERR("nats_tls_wolfssl: sanity-check failed -- loaded "
		       "'%s' does not export natsConnection_Connect (%s)\n",
		       nats_resolved_path,
		       dlerror() ? dlerror() : "no error string");
		dlclose(_handle);
		_handle = NULL;
		return -1;
	}

	LM_INFO("nats_tls_wolfssl: loaded '%s' (TLS backend = wolfSSL)\n",
	        nats_resolved_path);
	return 0;
}

static int mod_init(void)
{
	if (module_loaded("nats_tls_openssl")) {
		LM_ERR("nats_tls_wolfssl: nats_tls_openssl is also loaded; "
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
