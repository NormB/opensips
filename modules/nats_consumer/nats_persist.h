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
 * nats_persist.h -- opt-in JSON persistence of the nats_consumer handle
 * registry.  Phase 8.
 *
 * When enabled via the `persist_handles` modparam, the registry is
 * serialized to a JSON file on every bind/unbind (debounced 500 ms by a
 * dedicated background thread) and rehydrated on mod_init.  The file
 * stores only the bind-config fields -- runtime counters, subscriptions,
 * cached ack tokens, and the bind-order index are NOT persisted.
 *
 * Format: JSON array of objects, one per handle.  Only non-default
 * fields are emitted so the file stays readable.  Deserialization
 * canonicalizes each object back into the same k=v config string the
 * bind MI command accepts, so all validation funnels through the
 * existing nats_handle_parse() path.
 *
 * Thread model:
 *   - nats_persist_init() spawns a writer thread.
 *   - SIP workers / MI / consumer process call schedule_write() which
 *     just bumps a dirty counter + timestamp under a small mutex.
 *   - The writer thread wakes every 100 ms, checks the dirty flag, and
 *     when it is >= 500 ms old performs a serialize + tempfile write +
 *     fsync + atomic rename.
 *   - nats_persist_destroy() asks the thread to exit, joins it, and
 *     flushes any outstanding dirty state synchronously.
 *
 * All functions are safe to call when persistence is disabled: they
 * become no-ops.
 */

#ifndef NATS_PERSIST_H
#define NATS_PERSIST_H

/* Initialize the persistence subsystem with the given file path.
 *
 * Verifies the parent directory exists; if not, logs a warning and
 * returns -1 (persistence is considered disabled for this run).
 *
 * On success the writer thread is started and the caller may invoke
 * nats_persist_rehydrate() and/or nats_persist_schedule_write() from
 * any thread.
 *
 * Call AFTER nats_registry_init() -- rehydrate walks into the registry.
 *
 * Returns:
 *    0 on success,
 *   -1 if the file path is invalid or the parent directory is missing
 *      (caller should treat persistence as disabled),
 *   -2 on internal error (thread spawn, mutex init). */
int nats_persist_init(const char *path);

/* Stop the writer thread, flush any outstanding dirty state, and free
 * internal state.  Safe to call if init never ran or returned non-zero. */
void nats_persist_destroy(void);

/* Returns 1 if persistence is currently active (init succeeded + thread
 * running), 0 otherwise.  Used by MI reload to reject with a clear error
 * if the module was started with persistence off. */
int nats_persist_enabled(void);

/* Mark the registry dirty so the writer thread emits a new snapshot on
 * its next wake-up.  Safe no-op if persistence is not enabled.
 *
 * Called from bind/unbind paths (see nats_handle_registry.c). */
void nats_persist_schedule_write(void);

/* Force a synchronous write of the current registry state to disk.
 * Returns 0 on success, negative on error.  Used by mod_destroy to
 * flush pending dirty state and by the test harness to bypass the
 * debounce.  No-op when persistence is disabled. */
int nats_persist_flush_now(void);

/* Read the configured file, parse the JSON array, and for each object
 * synthesize a canonical bind-config string + run it through
 * nats_handle_parse() + nats_registry_bind().
 *
 * Duplicates (handle already bound under the same id) are logged and
 * skipped -- the caller is responsible for deciding whether a reload
 * should replace or merge.  Parse failures on individual objects are
 * logged and skipped; the function continues with the next object.
 *
 * Returns the number of handles successfully bound, or -1 on fatal
 * error (file missing, JSON root is not an array).  "File missing" is
 * a soft failure: returns 0, logs info, no error. */
int nats_persist_rehydrate(void);

#endif /* NATS_PERSIST_H */
