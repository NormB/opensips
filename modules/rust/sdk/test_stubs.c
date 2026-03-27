/*
 * Stub implementations of OpenSIPS core symbols for test builds.
 *
 * These are weak symbols that satisfy the linker for test binaries.
 * When loaded into OpenSIPS (the real core), the strong symbols from
 * the core take precedence. For cdylib builds, the linker leaves
 * these as undefined (resolved at dlopen), so they never conflict.
 */

#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

/* ── dprint.h symbols ─────────────────────────────────────────────── */
__attribute__((weak)) char ctime_buf[128];

/* log_level is declared as `extern int *log_level` in dprint.h */
static int _stub_log_level = 4;
__attribute__((weak)) int *log_level = &_stub_log_level;

__attribute__((weak)) char *log_prefix = "";
__attribute__((weak)) int dp_my_pid(void) { return 0; }
__attribute__((weak)) int log_facility = 0;

/* Match the real OpenSIPS dprint() signature exactly.
 * The variadic args are formatted for stderr_fmt/syslog_fmt, NOT format,
 * so we use stderr_fmt for output (it has the full pattern). */
__attribute__((weak))
void dprint(int level, int facility, const char *module, const char *func,
    char *stderr_fmt, char *syslog_fmt, char *format, ...) {
    (void)level; (void)facility; (void)module; (void)func;
    (void)syslog_fmt; (void)format;
    if (stderr_fmt) {
        va_list ap;
        va_start(ap, format);
        vfprintf(stderr, stderr_fmt, ap);
        va_end(ap);
        fputc('\n', stderr);
    }
}

/* ── ip_addr symbols ──────────────────────────────────────────────── */
struct ip_addr_buf { char buf[64]; };
__attribute__((weak)) struct ip_addr_buf _ip_addr_A_buffs[4];

/* ── Memory allocator stubs (pkg + shm) ──────────────────────────── */
__attribute__((weak))
void *gen_pkg_malloc(void *blk, unsigned long size,
                     const char *file, const char *func, unsigned int line) {
    (void)blk; (void)file; (void)func; (void)line;
    return malloc(size);
}
__attribute__((weak))
void gen_pkg_free(void *blk, void *p,
                  const char *file, const char *func, unsigned int line) {
    (void)blk; (void)file; (void)func; (void)line;
    free(p);
}
__attribute__((weak))
void *gen_shm_malloc(void *blk, unsigned long size,
                     const char *file, const char *func, unsigned int line) {
    (void)blk; (void)file; (void)func; (void)line;
    return malloc(size);
}
__attribute__((weak))
void *gen_shm_realloc(void *blk, void *p, unsigned long size,
                      const char *file, const char *func, unsigned int line) {
    (void)blk; (void)file; (void)func; (void)line;
    return realloc(p, size);
}
__attribute__((weak))
void gen_shm_free(void *blk, void *p,
                  const char *file, const char *func, unsigned int line) {
    (void)blk; (void)file; (void)func; (void)line;
    free(p);
}
__attribute__((weak))
unsigned long gen_shm_get_size(void *blk) { (void)blk; return 0; }
__attribute__((weak))
unsigned long gen_shm_get_rused(void *blk) { (void)blk; return 0; }

/* ── Memory block pointers ────────────────────────────────────────── */
__attribute__((weak)) void *mem_block = NULL;
__attribute__((weak)) void *mem_lock = NULL;
__attribute__((weak)) void *mem_dbg_lock = NULL;
__attribute__((weak)) void *shm_block = NULL;
__attribute__((weak)) void *shm_dbg_block = NULL;

/* ── SHM event/hist stubs ─────────────────────────────────────────── */
__attribute__((weak)) unsigned long event_shm_last = 0;
__attribute__((weak)) unsigned long event_shm_pending = 0;
__attribute__((weak)) unsigned long event_shm_threshold = 0;
__attribute__((weak))
void shm_event_raise(long used, long size, long perc) {
    (void)used; (void)size; (void)perc;
}
__attribute__((weak)) unsigned long shm_frag_size = 0;
__attribute__((weak)) void *shm_hist = NULL;
__attribute__((weak)) int shm_skip_sh_log = 0;
__attribute__((weak)) int shm_use_global_lock = 0;

/* ── Shared memory history stubs ──────────────────────────────────── */
__attribute__((weak))
int _sh_log(void *hist, int ref, const char *file, const char *func, int line) {
    (void)hist; (void)ref; (void)file; (void)func; (void)line;
    return 0;
}
__attribute__((weak))
int _sh_push(void *hist, void *frag) {
    (void)hist; (void)frag;
    return 0;
}
__attribute__((weak))
int _sh_unref(void *hist, void *frag) {
    (void)hist; (void)frag;
    return 0;
}

/* ── Module/parser stubs ──────────────────────────────────────────── */
__attribute__((weak))
void *find_export(const char *name, int flags) {
    (void)name; (void)flags;
    return NULL;
}
__attribute__((weak))
int parse_headers_aux(void *msg, unsigned long long flags, int next) {
    (void)msg; (void)flags; (void)next;
    return -1;
}

