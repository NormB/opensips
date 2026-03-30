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

#ifndef _EV_NATS_H_
#define _EV_NATS_H_

/* transport protocol name */
#define NATS_NAME    "nats"
#define NATS_STR     { NATS_NAME, sizeof(NATS_NAME) - 1 }
/* module flag — unique bit position among EVI transports */
#define NATS_FLAG    (1 << 25)

#ifndef NATS_DEFAULT_URL
#define NATS_DEFAULT_URL "nats://127.0.0.1:4222"
#endif

#endif /* _EV_NATS_H_ */
