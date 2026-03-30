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

#ifndef NATS_PRODUCER_H
#define NATS_PRODUCER_H

#include <nats/nats.h>

/* Set connection handles from child_init */
void nats_producer_set_connection(natsConnection *nc);
void nats_producer_set_js(jsCtx *js);

/* Direct publish — non-blocking (nats.c buffers internally) */
int nats_publish(const char *subject, const void *data, int len);

/* JetStream publish with async ack — falls back to nats_publish if no JS */
int nats_js_publish_async(const char *subject, const void *data, int len);

#endif
