/*
 * MAXFWD module
 *
 * Copyright (C) 2001-2003 FhG Fokus
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 *
 * History:
 * --------
 *  2003-03-11  updated to the new module interface (andrei)
 *  2003-03-16  flags export parameter added (janakj)
 *  2003-03-19  all mallocs/frees replaced w/ pkg_malloc/pkg_free (andrei)
 *  2004-08-15  max value of max-fwd header is configurable via max_limit
 *              module param (bogdan)
 *  2005-09-15  max_limit param cannot be disabled anymore (according to RFC)
 *              (bogdan)
 *  2005-11-03  is_maxfwd_lt() function added; MF value saved in
 *              msg->maxforwards->parsed (bogdan)
 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "../../sr_module.h"
#include "../../dprint.h"
#include "../../error.h"
#include "../../ut.h"
#include "../../mem/mem.h"
#include "mf_funcs.h"



#define MAXFWD_UPPER_LIMIT 256

static int max_limit = MAXFWD_UPPER_LIMIT;

static int fixup_maxfwd_header(void** param);
static int w_process_maxfwd_header(struct sip_msg* msg, int* mval);
static int is_maxfwd_lt(struct sip_msg *msg, int *limit);
static int mod_init(void);


static const cmd_export_t cmds[]={
	{"mf_process_maxfwd_header", (cmd_function)w_process_maxfwd_header, {
		{CMD_PARAM_INT, fixup_maxfwd_header, 0}, {0,0,0}},
		REQUEST_ROUTE},
	{"is_maxfwd_lt", (cmd_function)is_maxfwd_lt, {
		{CMD_PARAM_INT, fixup_maxfwd_header, 0}, {0,0,0}},
		REQUEST_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE},
	{0,0,{{0,0,0}},0}
};

static const param_export_t params[]={
	{"max_limit",    INT_PARAM,  &max_limit},
	{0,0,0}
};



#ifdef STATIC_MAXFWD
struct module_exports maxfwd_exports = {
#else
struct module_exports exports= {
#endif
	"maxfwd",
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /* dlopen flags */
	0,				 /* load function */
	NULL,            /* OpenSIPS module dependencies */
	cmds,
	0,
	params,
	0,          /* exported statistics */
	0,          /* exported MI functions */
	0,          /* exported pseudo-variables */
	0,			/* exported transformations */
	0,          /* extra processes */
	0,          /* pre-init function */
	mod_init,
	(response_function) 0,
	(destroy_function) 0,
	0,          /* per-child init function */
	0           /* reload confirm function */
};



static int mod_init(void)
{
	LM_INFO("initializing...\n");
	if ( max_limit<1 || max_limit>MAXFWD_UPPER_LIMIT ) {
		LM_ERR("invalid max limit (%d) [1,%d]\n",
			max_limit,MAXFWD_UPPER_LIMIT);
		return E_CFG;
	}
	return 0;
}



static int fixup_maxfwd_header(void** param)
{
	if (*(int*)*param<1 || *(int*)*param>MAXFWD_UPPER_LIMIT){
		LM_ERR("invalid MAXFWD number <%d> [1,%d]\n",
			*(int*)*param,MAXFWD_UPPER_LIMIT);
		return E_UNSPEC;
	}
	if (*(int*)*param>max_limit) {
		LM_ERR("default value <%d> bigger than max limit(%d)\n",
			*(int*)*param, max_limit);
		return E_UNSPEC;
	}

	return 0;
}



static int w_process_maxfwd_header(struct sip_msg* msg, int* mval)
{
	int val;
	str mf_value;

	val=is_maxfwd_present(msg, &mf_value);
	switch (val) {
		/* header not found */
		case -1:
			if (add_maxfwd_header( msg, *mval)!=0)
				goto error;
			return 2;
		/* error */
		case -2:
			goto error;
		/* found */
		case 0:
			return -1;
		default:
			if (val>max_limit){
				LM_DBG("value %d decreased to %d\n", val, max_limit);
				val = max_limit+1;
			}
			if ( decrement_maxfwd(msg, val, &mf_value)!=0 ) {
				LM_ERR("decrement failed!\n");
				goto error;
			}
	}

	return 1;
error:
	return -2;
}



static int is_maxfwd_lt(struct sip_msg *msg, int *limit)
{
	str mf_value;
	int val;

	val = is_maxfwd_present( msg, &mf_value);
	LM_DBG("value = %d, limit = %d\n", val, *limit);

	if ( val<0 ) {
		/* error or not found */
		/* coverity[return_overflow: FALSE] */
		return val-1;
	} else if ( val >= *limit ) {
		/* greater or equal than/to limit */
		return -1;
	}

	return 1;
}

