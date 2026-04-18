/*
 * dlg_profile_helper.c — Call set_dlg_profile() from C to avoid Rust's
 * compiler-generated panic cleanup code that triggers the aarch64 cdylib
 * vtable codegen bug.
 *
 * The Rust compiler generates deallocation cleanup paths using the broken
 * <Global as Allocator>::deallocate() vtable dispatch even when the function
 * only uses pkg_malloc. Moving this logic to C eliminates the Rust cleanup
 * code entirely.
 */

#include "cmds.h"
#include "mem/mem.h"
#include "dprint.h"
#include "route_struct.h"

#include <string.h>

/* Forward declarations — these are in action.h but pulling in all of
   action.h drags in the entire OpenSIPS dependency tree which breaks
   the standalone cc-rs build. */
int fix_cmd(const struct cmd_param *params, action_elem_t *elems);
int get_cmd_fixups(struct sip_msg *msg, const struct cmd_param *params,
                   action_elem_t *elems, void **cmdp, pv_value_t *tmp_vals);
int free_cmd_fixups(const struct cmd_param *params, action_elem_t *elems,
                    void **cmdp);

/* Cached command pointer — looked up once, reused. */
static const cmd_export_t *dlg_profile_cmd = NULL;

/* STR_ST from route_struct.h */
#ifndef STR_ST
#define STR_ST 12
#endif

/*
 * call_set_dlg_profile_c — Call set_dlg_profile(profile, account) via the
 * OpenSIPS script function mechanism.
 *
 * All memory is pkg-allocated and freed within this function.
 * Returns 0 on success, -1 on failure.
 */
int call_set_dlg_profile_c(
    struct sip_msg *msg,
    const char *profile_name, int profile_len,
    const char *account, int account_len)
{
    action_elem_t elems[MAX_ACTION_ELEMS];
    void *cmd_params[MAX_ACTION_ELEMS - 1];
    pv_value_t tmp_vals[MAX_ACTION_ELEMS - 1];
    str *pkg_profile = NULL;
    char *pkg_profile_buf = NULL;
    str *pkg_account = NULL;
    char *pkg_account_buf = NULL;
    int rc, ret = -1;

    /* Look up the command once */
    if (!dlg_profile_cmd) {
        dlg_profile_cmd = find_cmd_export_t("set_dlg_profile", 0);
        if (!dlg_profile_cmd) {
            LM_ERR("set_dlg_profile not found - is dialog.so loaded?\n");
            return -1;
        }
    }

    /* Allocate profile str in pkg memory */
    pkg_profile = pkg_malloc(sizeof(str));
    if (!pkg_profile) goto cleanup;
    pkg_profile_buf = pkg_malloc(profile_len + 1);
    if (!pkg_profile_buf) goto cleanup;
    memcpy(pkg_profile_buf, profile_name, profile_len);
    pkg_profile_buf[profile_len] = '\0';
    pkg_profile->s = pkg_profile_buf;
    pkg_profile->len = profile_len;

    /* Allocate account str in pkg memory */
    pkg_account = pkg_malloc(sizeof(str));
    if (!pkg_account) goto cleanup;
    pkg_account_buf = pkg_malloc(account_len + 1);
    if (!pkg_account_buf) goto cleanup;
    memcpy(pkg_account_buf, account, account_len);
    pkg_account_buf[account_len] = '\0';
    pkg_account->s = pkg_account_buf;
    pkg_account->len = account_len;

    /* Build action_elem_ array */
    memset(elems, 0, sizeof(elems));
    elems[1].type = STR_ST;
    elems[1].u.data = pkg_profile;
    elems[2].type = STR_ST;
    elems[2].u.data = pkg_account;

    /* Run fixups */
    rc = fix_cmd(dlg_profile_cmd->params, elems);
    if (rc < 0) {
        LM_ERR("fix_cmd failed for set_dlg_profile\n");
        goto cleanup;
    }

    /* Get fixups and call */
    memset(cmd_params, 0, sizeof(cmd_params));
    memset(tmp_vals, 0, sizeof(tmp_vals));

    rc = get_cmd_fixups(msg, dlg_profile_cmd->params, elems,
                        cmd_params, tmp_vals);
    if (rc < 0) {
        LM_ERR("get_cmd_fixups failed for set_dlg_profile\n");
        goto free_fixups;
    }

    /* Call the function */
    ret = dlg_profile_cmd->function(msg,
        cmd_params[0], cmd_params[1], cmd_params[2], cmd_params[3],
        cmd_params[4], cmd_params[5], cmd_params[6], cmd_params[7]);

free_fixups:
    free_cmd_fixups(dlg_profile_cmd->params, elems, cmd_params);

cleanup:
    if (pkg_account_buf) pkg_free(pkg_account_buf);
    if (pkg_account) pkg_free(pkg_account);
    if (pkg_profile_buf) pkg_free(pkg_profile_buf);
    if (pkg_profile) pkg_free(pkg_profile);

    return ret;
}
