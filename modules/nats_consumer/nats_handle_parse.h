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
 * nats_handle_parse.h -- parse a k=v;k=v bind-parameter string into a
 * freshly-allocated nats_handle_t.
 */

#ifndef NATS_HANDLE_PARSE_H
#define NATS_HANDLE_PARSE_H

#include "../../str.h"
#include "nats_handle_registry.h"

/* Parse a semicolon-separated k=v config string into a freshly-allocated
 * SHM handle.  Caller owns the returned handle -- pass it to
 * nats_registry_bind (which takes ownership) or nats_handle_free.
 *
 * Unknown keys are rejected as config errors.
 *
 * On parse error, returns NULL and sets *err to a borrowed static string
 * describing the first error.  *err must not be freed.
 */
nats_handle_t *nats_handle_parse(const str *config_str, const char **err);

#endif /* NATS_HANDLE_PARSE_H */
