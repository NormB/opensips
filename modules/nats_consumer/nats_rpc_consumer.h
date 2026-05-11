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
 * nats_rpc_consumer.h -- consumer-process side of the
 * consumer-process-routed async nats_request transport.
 *
 * All three functions below are called from the dedicated
 * nats_consumer process (not from SIP workers).  They set up a
 * persistent libnats subscription on
 * `_INBOX.opensips.<consumer_pid>.>`, drain the worker -> consumer
 * IPC queue and publish for each entry, and on each reply land
 * the payload into the corresponding SHM slot + signal the
 * worker's pre-allocated wake_fd.
 *
 * The libnats subscription callback runs on a libnats internal
 * thread inside the consumer process.  That context is known
 * safe for libnats threading (it's the same place where
 * JetStream pull subscriptions live today); the earlier
 * worker-side subscription pattern -- which crashed -- is gone.
 */

#ifndef NATS_RPC_CONSUMER_H
#define NATS_RPC_CONSUMER_H

/*
 * Set up the persistent inbox subscription against the consumer
 * process's libnats connection.  Called once from
 * nats_consumer_proc_main() after nats_pool_get() returns OK.
 *
 * The wildcard subscribed to is
 * `_INBOX.opensips.<consumer_pid>.>`; each in-flight publish
 * sets reply-to to `_INBOX.opensips.<consumer_pid>.<slot_idx>`
 * so the callback can look the slot up in O(1) without a hash.
 *
 * Returns 0 on success, -1 on subscribe failure (pool down,
 * permission denied, etc.).  Non-fatal: the consumer continues
 * doing JetStream pull work even if the inbox subscription
 * fails; the async-request path will see ABANDONED state on
 * every call and surface -3 to scripts.
 */
int nats_rpc_consumer_subscribe(void);

/*
 * Tear down the inbox subscription.  Called once at consumer
 * shutdown (before nats_pool teardown). */
void nats_rpc_consumer_unsubscribe(void);

/*
 * Drain the worker -> consumer publish IPC queue.  Called from
 * the consumer's main loop alongside the ack-IPC drain.
 * Returns the number of publishes processed.  Each entry reads
 * the slot's out_* fields and calls natsConnection_PublishMsg
 * with the reply-to subject pointing back at our inbox.
 */
int nats_rpc_consumer_drain_ipc(void);

#endif /* NATS_RPC_CONSUMER_H */
