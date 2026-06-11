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
 * nats_mi.h -- MI command declarations for the nats_consumer registry.
 */

#ifndef NATS_MI_H
#define NATS_MI_H

#include "../../mi/item.h"
#include "../../mi/mi.h"

mi_response_t *mi_consumer_bind(const mi_params_t *params,
		struct mi_handler *async);
mi_response_t *mi_consumer_unbind(const mi_params_t *params,
		struct mi_handler *async);
mi_response_t *mi_consumer_list(const mi_params_t *params,
		struct mi_handler *async);
mi_response_t *mi_consumer_stats(const mi_params_t *params,
		struct mi_handler *async);
mi_response_t *mi_handle_reload(const mi_params_t *params,
		struct mi_handler *async);
mi_response_t *mi_consumer_health(const mi_params_t *params,
		struct mi_handler *async);

extern const mi_export_t nats_consumer_mi_cmds[];

#endif /* NATS_MI_H */
