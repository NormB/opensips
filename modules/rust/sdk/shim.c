/*
 * C shim for OpenSIPS Rust SDK.
 *
 * Wraps variadic macros, static inline functions, and macro-based
 * memory allocators that cannot be called directly from Rust FFI.
 */

#include "dprint.h"
#include "mem/mem.h"
#include "mem/shm_mem.h"
#include "ip_addr.h"
#include "parser/msg_parser.h"
#include "pvar.h"
#include "action.h"
#include "route_struct.h"
#include "sr_module.h"

/* ── Logging ──────────────────────────────────────────────────────── */

void opensips_rs_log(int level, const char *module, const char *msg)
{
    LM_GEN1(level, "[%s] %s", module, msg);
}

/* ── Memory allocators ────────────────────────────────────────────── */

void *opensips_rs_pkg_malloc(unsigned long size)
{
    return pkg_malloc(size);
}

void opensips_rs_pkg_free(void *p)
{
    if (p)
        pkg_free(p);
}

void *opensips_rs_shm_malloc(unsigned long size)
{
    return shm_malloc(size);
}

void opensips_rs_shm_free(void *p)
{
    if (p)
        shm_free(p);
}

/* ── ip_addr2a wrapper (static inline in ip_addr.h) ──────────────── */

const char *opensips_rs_ip_addr2a(struct ip_addr *ip)
{
    return ip_addr2a(ip);
}

/* ── sip_msg field accessors ──────────────────────────────────────── */

int opensips_rs_msg_method(struct sip_msg *msg, const char **out, int *len)
{
    if (!msg || msg->first_line.type != SIP_REQUEST)
        return -1;
    *out = msg->first_line.u.request.method.s;
    *len = msg->first_line.u.request.method.len;
    return 0;
}

int opensips_rs_msg_ruri(struct sip_msg *msg, const char **out, int *len)
{
    if (!msg || msg->first_line.type != SIP_REQUEST)
        return -1;
    *out = msg->first_line.u.request.uri.s;
    *len = msg->first_line.u.request.uri.len;
    return 0;
}

int opensips_rs_msg_status(struct sip_msg *msg, const char **out, int *len)
{
    if (!msg || msg->first_line.type != SIP_REPLY)
        return -1;
    *out = msg->first_line.u.reply.status.s;
    *len = msg->first_line.u.reply.status.len;
    return 0;
}

int opensips_rs_msg_status_code(struct sip_msg *msg)
{
    if (!msg || msg->first_line.type != SIP_REPLY)
        return -1;
    return (int)msg->first_line.u.reply.statuscode;
}

const char *opensips_rs_msg_src_ip(struct sip_msg *msg)
{
    if (!msg)
        return NULL;
    return ip_addr2a(&msg->rcv.src_ip);
}

unsigned short opensips_rs_msg_src_port(struct sip_msg *msg)
{
    if (!msg)
        return 0;
    return msg->rcv.src_port;
}

int opensips_rs_msg_type(struct sip_msg *msg)
{
    if (!msg)
        return 0;
    return msg->first_line.type;
}

unsigned int opensips_rs_msg_flags(struct sip_msg *msg)
{
    if (!msg)
        return 0;
    return msg->flags;
}

void opensips_rs_msg_set_flag(struct sip_msg *msg, unsigned int flag)
{
    if (msg)
        msg->flags |= (1u << flag);
}

void *opensips_rs_msg_headers(struct sip_msg *msg)
{
    if (!msg)
        return NULL;
    return msg->headers;
}

int opensips_rs_hdr_name(void *hdr, const char **out, int *len)
{
    struct hdr_field *h = (struct hdr_field *)hdr;
    if (!h) return -1;
    *out = h->name.s;
    *len = h->name.len;
    return 0;
}

int opensips_rs_hdr_body(void *hdr, const char **out, int *len)
{
    struct hdr_field *h = (struct hdr_field *)hdr;
    if (!h) return -1;
    *out = h->body.s;
    *len = h->body.len;
    return 0;
}

void *opensips_rs_hdr_next(void *hdr)
{
    struct hdr_field *h = (struct hdr_field *)hdr;
    if (!h) return NULL;
    return h->next;
}

int opensips_rs_parse_headers(struct sip_msg *msg)
{
    if (!msg)
        return -1;
    return parse_headers(msg, HDR_EOH_F, 0);
}

/* ── PV helpers ───────────────────────────────────────────────────── */

int opensips_rs_pv_is_writable(pv_spec_t *sp)
{
    if (!sp)
        return 0;
    return (sp->setf != NULL) ? 1 : 0;
}

/* ── Version strings for module registration ──────────────────────── */

#include "version.h"

const char *opensips_rs_full_version(void)
{
    return OPENSIPS_FULL_VERSION;
}

const char *opensips_rs_compile_flags(void)
{
    return OPENSIPS_COMPILE_FLAGS;
}

/* ── Dialog module API wrappers ───────────────────────────────────── */
/* dlg_load.h pulls in too many transitive deps for bindgen, so we
 * wrap the static-inline load_dlg_api() and provide thin accessors
 * for the loaded function pointers. */

#include "modules/dialog/dlg_load.h"

/* Opaque storage for the loaded dialog API.
 * Callers use opensips_rs_dlg_register_cb() etc. instead of reaching in. */
static struct dlg_binds __dlg_api;
static int __dlg_api_loaded = 0;

int opensips_rs_load_dlg_api(void)
{
    if (__dlg_api_loaded)
        return 0;
    if (load_dlg_api(&__dlg_api) < 0)
        return -1;
    __dlg_api_loaded = 1;
    return 0;
}

int opensips_rs_dlg_api_loaded(void)
{
    return __dlg_api_loaded;
}

/* Register a dialog callback via the loaded API.
 * @dlg: NULL for global (DLGCB_CREATED), or a specific dlg_cell* for per-dialog.
 * @cb_types: bitmask of DLGCB_* constants.
 * @cb: the extern "C" callback function.
 * @param: opaque user pointer passed to the callback.
 * @param_free: cleanup function for param (may be NULL).
 */
int opensips_rs_dlg_register_cb(void *dlg, int cb_types,
    dialog_cb cb, void *param, param_free_cb param_free)
{
    if (!__dlg_api_loaded)
        return -1;
    return __dlg_api.register_dlgcb(
        (struct dlg_cell *)dlg, cb_types, cb, param, param_free);
}

/* Extract the Call-ID from an opaque dlg_cell pointer.
 * Returns pointer into shared memory (do not free). */
int opensips_rs_dlg_callid(void *dlg, const char **out, int *len)
{
    struct dlg_cell *d = (struct dlg_cell *)dlg;
    if (!d)
        return -1;
    *out = d->callid.s;
    *len = d->callid.len;
    return 0;
}

/* Get the current dialog from context (equivalent to get_dlg()). */
void *opensips_rs_dlg_get_ctx(void)
{
    if (!__dlg_api_loaded || !__dlg_api.get_dlg)
        return NULL;
    return __dlg_api.get_dlg();
}

/* Create a dialog for the current INVITE (calls create_dlg). */
int opensips_rs_dlg_create(void *msg, int flags)
{
    if (!__dlg_api_loaded || !__dlg_api.create_dlg)
        return -1;
    return __dlg_api.create_dlg((struct sip_msg *)msg, flags);
}
