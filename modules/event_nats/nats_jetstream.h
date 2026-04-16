/*
 * Copyright (C) 2025 Summit-2026 / event_nats contributors
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
 *
 */

/*
 * nats_jetstream.h — JetStream Management MI Commands
 *
 * Module:  event_nats
 *
 * MI commands for JetStream cluster administration:
 *   nats_account_info      — account stats (memory, storage, streams, consumers)
 *   nats_stream_list       — list all streams
 *   nats_stream_info       — detailed stream metadata
 *   nats_stream_create     — create a new stream
 *   nats_stream_delete     — delete a stream
 *   nats_stream_purge      — purge all messages in a stream
 *   nats_consumer_list     — list consumers for a stream
 *   nats_consumer_info     — detailed consumer metadata
 *   nats_consumer_create   — create a consumer
 *   nats_consumer_delete   — delete a consumer
 *   nats_msg_get           — get a message by sequence number
 *   nats_msg_delete        — delete a message by sequence number
 */

#ifndef _NATS_JETSTREAM_H_
#define _NATS_JETSTREAM_H_

#include "../../mi/mi.h"

/* Account info */
mi_response_t *mi_nats_account_info(const mi_params_t *params,
    struct mi_handler *async_hdl);

/* Stream management */
mi_response_t *mi_nats_stream_list(const mi_params_t *params,
    struct mi_handler *async_hdl);

mi_response_t *mi_nats_stream_info(const mi_params_t *params,
    struct mi_handler *async_hdl);

mi_response_t *mi_nats_stream_create(const mi_params_t *params,
    struct mi_handler *async_hdl);

mi_response_t *mi_nats_stream_delete(const mi_params_t *params,
    struct mi_handler *async_hdl);

mi_response_t *mi_nats_stream_purge(const mi_params_t *params,
    struct mi_handler *async_hdl);

/* Consumer management */
mi_response_t *mi_nats_consumer_list(const mi_params_t *params,
    struct mi_handler *async_hdl);

mi_response_t *mi_nats_consumer_info(const mi_params_t *params,
    struct mi_handler *async_hdl);

mi_response_t *mi_nats_consumer_create(const mi_params_t *params,
    struct mi_handler *async_hdl);

mi_response_t *mi_nats_consumer_delete(const mi_params_t *params,
    struct mi_handler *async_hdl);

/* Message operations */
mi_response_t *mi_nats_msg_get(const mi_params_t *params,
    struct mi_handler *async_hdl);

mi_response_t *mi_nats_msg_delete(const mi_params_t *params,
    struct mi_handler *async_hdl);

#endif /* _NATS_JETSTREAM_H_ */
