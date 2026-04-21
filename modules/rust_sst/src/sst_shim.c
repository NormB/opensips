/*
 * sst_shim.c — Minimal C-side helpers for rust_sst's dialog-state tracker.
 *
 * Rationale: Rust code on aarch64 cdylib (rustc 1.94) miscompiles trait
 * vtable dispatch. Touching std collections / Box / format! / catch_unwind
 * from a dialog callback reliably SIGSEGVs. This shim exposes the few
 * dlg_cell fields rust_sst needs (h_id, h_entry, lifetime, start_ts) via
 * plain C accessors so the Rust trampolines can stay primitive-only.
 */

#include "modules/dialog/dlg_hash.h"
#include <time.h>

/* Extract the stable (h_entry, h_id) identity pair + lifetime + start_ts
 * from a dlg_cell pointer. All outputs are by-ref so the Rust caller can
 * keep the whole thing in registers / a stack struct — no trait dispatch.
 *
 * Returns 0 on success, -1 if dlg is NULL. */
int rust_sst_dlg_ids(void *dlg_ptr,
                     unsigned int *h_entry,
                     unsigned int *h_id,
                     unsigned int *lifetime,
                     unsigned int *start_ts)
{
    struct dlg_cell *d = (struct dlg_cell *)dlg_ptr;
    if (!d) return -1;
    if (h_entry)  *h_entry  = d->h_entry;
    if (h_id)     *h_id     = d->h_id;
    if (lifetime) *lifetime = d->lifetime;
    if (start_ts) *start_ts = d->start_ts;
    return 0;
}

/* Thin wrapper so Rust doesn't need to bind <time.h>. */
long long rust_sst_now_unix(void)
{
    return (long long)time(NULL);
}
