/*
 * Copyright (C) 2009 Voice Sistem SRL
 * Copyright (C) 2009 Andrei Dragus
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
 *
 * History:
 * ---------
 *  2009-09-04  first version (andreidragus)
 *  2017-12-12  use opensips_json_c_helper.h (besser82)
 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>

#include "../../sr_module.h"
#include "../../db/db.h"
#include "../../dprint.h"
#include "../../error.h"
#include "../../ut.h"
#include "../../pvar.h"
#include "../../mod_fix.h"
#include "../../script_cb.h"
#include "../../script_var.h"
#include "../../mem/mem.h"
#include "../../mi/mi.h"
#include "../tm/tm_load.h"
#include "../rr/api.h"
#include "../../lib/json/opensips_json_c_helper.h"


enum
{
	TAG_KEY = 1,
	TAG_IDX = 2,
	TAG_VAR = 4,
	TAG_END = 8
};

typedef struct json_object  json_t;

typedef struct _pv_json
{
	str name;
	json_t * data;
	struct _pv_json * next;

}pv_json_t;

typedef struct json_object_iterator  json_iter_t;

enum {
	ITER_NONE,
	ITER_KEYS,
	ITER_VALUES
};

typedef struct _tag_list
{
	int type;

	str key;
	int idx;
	pv_spec_t var;

	struct _tag_list * next;

}json_tag;

typedef struct _json_name
{
	str name;
	json_tag * tags;
	json_tag ** end;

	int iter_type;
	int iter_prev_idx;
	json_iter_t iter;

}json_name;

pv_json_t * all;
char buff[JSON_FILE_BUF_SIZE];
int json_long_quoting;

static int mod_init(void);
static int child_init(int );
static void mod_destroy(void);
static int fixup_json_bind(void**);
static int pv_set_json (struct sip_msg*,  pv_param_t*, int , pv_value_t* );
static int pv_get_json (struct sip_msg*,  pv_param_t*, pv_value_t* );
static int pv_get_json_compact(struct sip_msg*,  pv_param_t*, pv_value_t* );
static int pv_get_json_pretty(struct sip_msg*,  pv_param_t*, pv_value_t* );
static int pv_get_json_ext(struct sip_msg*,  pv_param_t*, pv_value_t* , int flags);
static int json_bind(struct sip_msg* , pv_spec_t* , pv_spec_t* );
static void print_tag_list( json_tag *, json_tag *, int);
static json_t *get_object(pv_json_t *, pv_param_t *, json_tag **, int, int);
static int pv_parse_json_name (pv_spec_p, const str *);
static int pv_parse_json_index(pv_spec_p sp, const str *in);
static pv_json_t * get_pv_json (pv_param_t* );
static int pv_add_json ( pv_param_t* , json_t * );
static int expand_tag_list( struct sip_msg*, json_tag *);
static int w_merge_json(struct sip_msg *msg, str *j1, str* j2, pv_spec_t *res);

static const cmd_export_t cmds[]={
	{"json_link",    (cmd_function)json_bind, {
		{CMD_PARAM_VAR, fixup_json_bind, 0},
		{CMD_PARAM_VAR, fixup_json_bind, 0}, {0,0,0}},
		REQUEST_ROUTE|ONREPLY_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|
		LOCAL_ROUTE|STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},
	{"json_merge",(cmd_function)w_merge_json, {
		{CMD_PARAM_STR, 0, 0}, 
		{CMD_PARAM_STR, 0, 0}, 
		{CMD_PARAM_VAR, 0, 0}, 
		{0,0,0}},
		ALL_ROUTES},
	{0,0,{{0,0,0}},0}
};

static const param_export_t mod_params[]={
	{ "enable_long_quoting",         INT_PARAM, &json_long_quoting       },
	{ 0,0,0 }
};


static const pv_export_t mod_items[] = {
	{ str_const_init("json"),    PVT_JSON, pv_get_json,
		pv_set_json, pv_parse_json_name, pv_parse_json_index, 0, 0},
	{ str_const_init("json_compact"), PVT_JSON, pv_get_json_compact,
		pv_set_json, pv_parse_json_name, 0, 0, 0},
	{ str_const_init("json_pretty"), PVT_JSON, pv_get_json_pretty,
		pv_set_json, pv_parse_json_name, 0, 0, 0},
	{ {0, 0}, 0, 0, 0, 0, 0, 0, 0 }
};

struct module_exports exports= {
	"json",        /* module's name */
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /* dlopen flags */
	0,               /* load function */
	NULL,            /* OpenSIPS module dependencies */
	cmds,            /* exported functions */
	0,               /* exported async functions */
	mod_params,      /* param exports */
	0,               /* exported statistics */
	0,               /* exported MI functions */
	mod_items,       /* exported pseudo-variables */
	0,               /* exported transformations */
	0,               /* extra processes */
	0,               /* module pre-initialization function */
	mod_init,        /* module initialization function */
	0,               /* reply processing function */
	mod_destroy,
	child_init,      /* per-child init function */
	0                /* reload confirm function */
};

int json_bind(struct sip_msg* msg, pv_spec_t* dest, pv_spec_t* src)
{
	pv_json_t * var ;
	json_t * obj;
	json_name * id ;
	pv_param_t *pvp;

	pvp = &src->pvp;

	id = (json_name *) pvp->pvn.u.dname;

	var = get_pv_json(pvp);

	if( var == NULL )
	{
		LM_ERR("Variable named:%.*s not found\n",id->name.len,id->name.s);
		return -1;
	}

	obj = get_object(var, pvp, NULL, 0, 1);


	if( obj == NULL )
	{
		LM_NOTICE("Could not find object with that path\n");
		return -1;
	}

	json_object_get(obj);

	if(  pv_add_json( &dest->pvp, obj ) )
		return -1;

	return 1;
};

int fixup_json_bind(void** param)
{
	if(pv_type(((pv_spec_t*)*param)->type) != PVT_JSON)
	{
		LM_ERR("Parameter must be a json variable\n");
		return -1;
	}

	return 0;
}




struct json_object* json_parse(const char *str,int len,enum json_tokener_error *status)
{
	struct json_tokener* tok;
	struct json_object* obj;

	tok = json_tokener_new();
	obj = json_tokener_parse_ex(tok, str, len);

	if( tok-> err == json_tokener_continue )
		obj = json_tokener_parse_ex(tok, "", -1);

	if(tok->err != json_tokener_success) {
		obj = NULL;
		if (status)
			*status = tok->err;
	}

	json_tokener_free(tok);
	return obj;
}



/* returns the variable designated by pvp */
pv_json_t * get_pv_json (pv_param_t* pvp)
{
	pv_json_t * cur;
	json_name * id = (json_name *) pvp->pvn.u.dname;

	cur = all;
	while( cur )
	{
		if( cur->name.len == id->name.len &&
			!strncmp(cur->name.s,id->name.s,cur->name.len) )
				break;
		cur = cur->next ;
	}

	return cur;

}





json_t *get_object(pv_json_t *var, pv_param_t *pvp, json_tag **tag,
				int get_prev_obj, int report_err)
{
	json_name * id = (json_name *) pvp->pvn.u.dname;
	json_t * cur_obj, * last_obj = 0;
	json_tag * cur_tag, * last_tag = 0;
	int poz;

	cur_tag = id->tags;
	cur_obj = var->data;

	while( cur_tag  )
	{
		last_tag = cur_tag;
		last_obj = cur_obj;

		if( cur_tag->type & TAG_KEY )
		{
			memcpy( buff, cur_tag->key.s, cur_tag->key.len );
			buff[cur_tag->key.len] = 0;

			if( cur_obj == NULL ||
				!json_object_is_type( cur_obj, json_type_object ) )
				goto error;

			if (!json_object_object_get_ex( cur_obj,buff, &cur_obj ) &&
				!get_prev_obj)
				goto error;
		}

		if( cur_tag->type & TAG_IDX )
		{

			if( cur_obj == NULL ||
				!json_object_is_type( cur_obj, json_type_array ) )
				goto error;


			poz = cur_tag->idx;

			if( cur_tag->type & TAG_END )
			{
				poz = json_object_array_length(cur_obj);
			}
			else
			{
				if( poz < 0 )
					poz += json_object_array_length(cur_obj);
			}


			if( poz < 0 )
				goto error;

			cur_obj = json_object_array_get_idx( cur_obj, poz );

			if( cur_obj == NULL && !get_prev_obj)
				goto error;

		}

		cur_tag = cur_tag->next;
	}

	if (tag)
		*tag = last_tag;

	if (get_prev_obj)
		return last_obj;
	else
		return cur_obj;

error:

	if( report_err)
	{
		LM_NOTICE("Trying to get a value from a json of incorrect type\n");
		if(var->data)
			LM_NOTICE("Object is:\n%s\n",
				json_object_to_json_string(var->data));
		else
			LM_NOTICE("Object is null\n");
		print_tag_list( id->tags, cur_tag->next, 1);
	}

	return NULL;

}

int pv_get_json(struct sip_msg* msg,  pv_param_t* pvp, pv_value_t* val)
{
	return pv_get_json_ext(msg, pvp, val, JSON_C_TO_STRING_SPACED);
}

int pv_get_json_compact(struct sip_msg* msg,  pv_param_t* pvp, pv_value_t* val)
{
	return pv_get_json_ext(msg, pvp, val, JSON_C_TO_STRING_PLAIN);
}

int pv_get_json_pretty(struct sip_msg* msg,  pv_param_t* pvp, pv_value_t* val)
{
	return pv_get_json_ext(msg, pvp, val, JSON_C_TO_STRING_PRETTY);
}

int pv_json_iterate(json_t **obj, pv_param_t *pvp, json_name *id, pv_value_t *val)
{
	json_iter_t iter_end;

	if (json_object_is_type(*obj, json_type_object)) {

		if (pvp->pvi.u.ival != id->iter_prev_idx + 1) {
			id->iter_prev_idx = 0;
			id->iter = json_object_iter_begin(*obj);
		} else
			id->iter_prev_idx++;

		iter_end = json_object_iter_end(*obj);
		if (json_object_iter_equal(&id->iter, &iter_end))
			return pv_get_null(NULL, pvp, val);

		if (id->iter_type == ITER_KEYS) {
			val->flags = PV_VAL_STR;
			val->rs.s = (char *)json_object_iter_peek_name(&id->iter);
			val->rs.len = strlen(val->rs.s);
		} else
			*obj = json_object_iter_peek_value(&id->iter);

		json_object_iter_next(&id->iter);	

	} else if (json_object_is_type(*obj, json_type_array)) {

		if (id->iter_type != ITER_NONE) {
			LM_DBG("Invalid object-like iteration for arrays\n");
			return -1;
		}

		if (pvp->pvi.u.ival == json_object_array_length(*obj)) {
			id->iter_prev_idx = 0;
			return pv_get_null(NULL, pvp, val);
		}

		*obj = json_object_array_get_idx(*obj, pvp->pvi.u.ival);

	} else {
		LM_DBG("Can only iterate over arrays or objects\n");
		return -1;
	}

	return 0;
}

int pv_get_json_ext(struct sip_msg* msg,  pv_param_t* pvp, pv_value_t* val, int flags)
{

	pv_json_t * var ;
	json_t * obj;
	json_name * id = (json_name *) pvp->pvn.u.dname;
	UNUSED(id);
	int64_t int_value;

	if( expand_tag_list( msg, ((json_name *)pvp->pvn.u.dname)->tags ) < 0)
	{
		LM_ERR("Cannot expand variables in path\n");
		return pv_get_null( msg, pvp, val);
	}


	var = get_pv_json(pvp);

	if( var == NULL )
	{
		/* this is not an error - we simply came across a json spec
		 * pointing a json var which was never set/init */
		LM_DBG("Variable named:%.*s not found\n",id->name.len,id->name.s);
		return pv_get_null( msg, pvp, val);
	}

	obj = get_object(var, pvp, NULL, 0, 0);

	memset(val, 0, sizeof(pv_value_t));

	if( obj == NULL )
		return pv_get_null( msg, pvp, val);

	if (pvp->pvi.type == PV_IDX_INT) {
		if (pv_json_iterate(&obj, pvp, id, val) < 0) {
			LM_DBG("Failed to iterate\n");
			return pv_get_null(msg, pvp, val);
		}

		if (val->flags == PV_VAL_STR || val->flags == PV_VAL_NULL)
			/* val is set */
			return 0;
		/* else we got an object */
	} else if (pvp->pvi.type == PV_IDX_ALL) {
		LM_ERR("\"[*]\" index only supported in for each statement\n");
		return pv_get_null(msg, pvp, val);
	}

	if( json_object_is_type(obj, json_type_int) )
	{
		int_value = json_object_get_int64(obj);
		val->rs.s = sint2str(int_value, &val->rs.len);

		if (!json_long_quoting || (int_value>=INT_MIN && int_value<=INT_MAX)) {
			/* safe to store it as an INT in the pvar */
			val->ri = int_value;
			val->flags |= PV_VAL_INT|PV_TYPE_INT|PV_VAL_STR;
		} else {
			/* we would overflow/underflow, store as string only */
			val->flags |= PV_VAL_STR;
		}
	}
	else if( json_object_is_type(obj, json_type_string))
	{
		val->flags = PV_VAL_STR;
		val->rs.s = (char*)json_object_get_string( obj );
#if JSON_C_VERSION_NUM >= JSON_C_VERSION_010
		val->rs.len = json_object_get_string_len( obj );
#else
		val->rs.len = strlen(val->rs.s);
#endif
	} else {
		val->flags = PV_VAL_STR;
		val->rs.s = (char*)json_object_to_json_string_ext( obj, flags);
		val->rs.len = strlen(val->rs.s);
	}

	return 0;
}


int pv_add_json ( pv_param_t* pvp, json_t * obj )
{
	json_t *dest;
	json_name * id;
	pv_json_t * var;
	json_tag * tag;
	int poz;


	id = (json_name *) pvp->pvn.u.dname;


	var = get_pv_json(pvp);

	if( var == NULL )
	{

		if( id->tags )
		{
			LM_ERR("Object is not initialized yet\n");
			return -1;
		}

		var = (pv_json_t *) pkg_malloc(sizeof(pv_json_t));

		if( var == NULL )
		{
			LM_ERR("Out of memory\n");
			return -1;
		}

		memset(var,0,sizeof(pv_json_t));

		var->name = id->name;
		var->next = all;

		var->data = obj;
		all = var;
		return 0;
	}


	if( id ->tags == NULL)
	{
		if( var->data )
			json_object_put(var->data);

		var->data = obj;
		return 0;
	}


	dest = get_object(var, pvp, &tag, 1, 1);

	if( dest == NULL )
	{
		LM_NOTICE("Could not find object with that path\n");
		return -1;
	}

	if( tag->type & TAG_KEY )
	{
		memcpy(buff,tag->key.s,tag->key.len);
		buff[tag->key.len] = 0;

		if( obj == NULL )
			json_object_object_del(dest,buff);
		else
			json_object_object_add(dest,buff,obj);
	}

	if( tag->type & TAG_IDX )
	{

		poz = tag->idx;

		if( tag->type & TAG_END )
		{
			if( obj == NULL)
			{
				LM_ERR("Invalid parameter for deletion\n");
				return -1;
			}

			json_object_array_add(dest,obj);
			return 0;

		}

		if(  poz < 0 )
			poz += json_object_array_length(dest);




		if( poz<0 || poz >= json_object_array_length(dest))
		{
			LM_ERR("Attempting to replace at invalid index in array:%d\n",
				poz);
			return -1;
		}

		if( obj == NULL)
		{
			if( poz >= json_object_array_length(dest))
			{
				LM_ERR("Index out of bounds for deletion\n");
				return -1;
			}

			json_object_array_del(dest,poz);
		}
		else
			json_object_array_put_idx(dest,poz,obj);
	}

	return 0;

}


int pv_set_json (struct sip_msg* msg,  pv_param_t* pvp, int flag ,
		pv_value_t* val)
{

	json_t * obj;
	enum json_tokener_error parse_status;


	if( expand_tag_list( msg, ((json_name *)pvp->pvn.u.dname)->tags ) < 0)
	{
		LM_ERR("Cannot expand variables in path\n");
		return -1;
	}

	/* delete value */
	if( val == NULL)
	{
		return pv_add_json(pvp,NULL);
	}


	/* If we want the value to be interpreted prepare the object */
	if( flag == COLONEQ_T )
	{

		if( ! (val->flags & PV_VAL_STR) )
		{
			LM_ERR("Trying to interpret a non-string value\n");
			return -1;
		}

		obj = json_parse( val->rs.s, val->rs.len,&parse_status);

		if (obj == NULL)
		{
			LM_ERR("Error parsing json: %s\n",
#if JSON_C_VERSION_NUM >= JSON_C_VERSION_010
				json_tokener_error_desc(parse_status)
#else
				json_tokener_errors[(unsigned long)obj]
#endif
			);

			pv_add_json(pvp, NULL);
			return -1;

		}

	}
	else
	{
		if( pvv_is_int(val))
		{
			obj = json_object_new_int(val->ri);
		}
		else
		{
			obj = json_object_new_string_len( val->rs.s, val->rs.len);
		}

	}



	return pv_add_json(pvp,obj);
}



enum
{
	ST_NAME = 0,
	ST_TEST = 1,
	ST_KEY = 2,
	ST_IDX = 3,
	ST_ITER = 4,
	ST_ERR = 5
};

#define NO_VALID_STATES 5

int next[NO_VALID_STATES][256];
int ignore[NO_VALID_STATES][256];
int inited;

int expand_tag_list( struct sip_msg* msg,json_tag * start)
{
	json_tag * cur = start;
	pv_value_t val;

	memset(&val,0,sizeof(pv_value_t));


	while(cur)
	{
		if( cur->type & TAG_VAR )
		{
			if( pv_get_spec_value(msg, &cur->var ,&val) < 0)
			{
				LM_ERR("Unable to get value from variable\n");
				return -1;
			}

			if( cur->type & TAG_IDX )
			{
				if( !(val.flags & PV_VAL_INT) )
				{
					LM_ERR("Non integer value in index\n");
					return -1;
				}

				cur->idx = val.ri;
			}

			if( cur->type & TAG_KEY )
			{
				if( !(val.flags & PV_VAL_STR) )
				{
					LM_ERR("Non string value in key\n");
					return -1;
				}

				cur->key = val.rs;
			}

		}
		cur = cur->next;
	}

	return 0;
};


void print_tag_list( json_tag * start, json_tag * end, int err)
{
	json_tag * cur = start;


	if( !err )
	{

		if( start == NULL )
		{
			LM_DBG("No tags were found\n");
		}
		else
		{
			LM_DBG("Tag list:\n");
		}

		while( cur != end )
		{
			if( cur->type & TAG_KEY)
				LM_DBG("key=[%.*s]\n",cur->key.len,cur->key.s);
			if( cur->type & TAG_IDX)
				LM_DBG("idx=[%d]\n",cur->idx);

			cur = cur->next;
		}
	}
	else
	{
		if( start == NULL )
		{
			LM_NOTICE("No tags were found\n");
		}
		else
		{
			LM_NOTICE("Tag list:\n");
		}

		while( cur != end )
		{
			if( cur->type & TAG_KEY)
				LM_NOTICE("key=[%.*s]\n",cur->key.len,cur->key.s);
			if( cur->type & TAG_IDX)
				LM_NOTICE("idx=[%d]\n",cur->idx);

			cur = cur->next;
		}

	}
}

int get_value(int state, json_name * id, char *start, char * cur)
{

	json_tag * node;
	char * i;
	int empty;
	str in;
	static str keys_s = str_init("keys");
	static str values_s = str_init("values");

	in.s = start;
	in.len = cur-start;

	if( state != ST_TEST )
		LM_DBG("JSON tag type=%d value=%.*s\n",state,(int)(cur-start),start);

	switch(state)
	{
		case ST_NAME:
			id->name = in;
			break;
		case ST_TEST:
			break;
		case ST_KEY:
			node = (json_tag *) pkg_malloc(sizeof(json_tag));

			if( node == NULL )
			{
				LM_ERR("Out of memory\n");
				return -1;
			}

			memset(node,0,sizeof(json_tag));
			node->type = TAG_KEY;

			*id->end = node;
			id->end = &node->next;

			if( in.len > 0 && *start == '$' )
			{
				if(!pv_parse_spec(&in, &node->var))
				{
					LM_ERR("Unable to parse variable\n");
					return -1;
				}

				node->type |= TAG_VAR;
				return 0;
			}


			node->key = in;

			break;
		case ST_IDX:
			node = (json_tag *) pkg_malloc(sizeof(json_tag));

			if( node == NULL )
			{
				LM_ERR("Out of memory\n");
				return -1;
			}

			memset(node,0,sizeof(json_tag));
			node->type = TAG_IDX;
			*id->end = node;
			id->end = &node->next;


			empty = 1;

			for( i=start; i<cur; i++)
				if( !isspace(*i) )
				{
					empty = 0;
					break;
				}

			if( empty)
			{
				node->type |= TAG_END;
				return 0;
			}


			if( *i == '$' )
			{
				if(!pv_parse_spec(&in, &node->var))
				{
					LM_ERR("Unable to parse variable\n");
					return -1;
				}

				node->type |= TAG_VAR;
				return 0;
			}

			if( sscanf( start, "%d", &node->idx ) != 1)
			{
				LM_ERR("Index value is not an integer:[%.*s]\n",
					(int)(cur-start), start );
				return -1;
			}

			break;
		case ST_ITER:
			if (str_match(&keys_s, &in))
				id->iter_type = ITER_KEYS;
			else if (str_match(&values_s, &in))
				id->iter_type = ITER_VALUES;
			else {
				LM_ERR("Bad iterator type\n");
				return -1;
			}

			break;
	}
	return 0;
}


void init_matrix(void)
{
	int i,j;

	/* point each state to itself */
	for( i=0; i<NO_VALID_STATES; i++)
		for( j=0; j<256; j++)
			next[i][j] = i;

	next[ST_NAME][(unsigned int)'/'] = ST_TEST;
	next[ST_NAME][(unsigned int)'['] = ST_TEST;
	next[ST_NAME][(unsigned int)'.'] = ST_TEST;

	for( j=0; j<256; j++)
		next[ST_TEST][j] = ST_ERR;

	next[ST_TEST][(unsigned int)'['] = ST_IDX;
	next[ST_TEST][(unsigned int)'/'] = ST_KEY;
	next[ST_TEST][(unsigned int)'.'] = ST_ITER;

	next[ST_IDX][(unsigned int)']'] = ST_TEST;

	next[ST_KEY][(unsigned int)'['] = ST_TEST;
	next[ST_KEY][(unsigned int)'/'] = ST_TEST;
	next[ST_KEY][(unsigned int)'.'] = ST_TEST;

	next[ST_ITER][(unsigned int)'['] = ST_ERR;
	next[ST_ITER][(unsigned int)'/'] = ST_ERR;
	next[ST_ITER][(unsigned int)'.'] = ST_ERR;

	/* set chars that will not be consumed */
	for( j=0; j<256; j++)
		ignore[ST_TEST][j] = 1;

	ignore[ST_NAME][(unsigned int)'/'] = 1;
	ignore[ST_TEST][(unsigned int)'/'] = 0;
	ignore[ST_KEY][(unsigned int)'/'] = 1;

	ignore[ST_NAME][(unsigned int)'['] = 1;
	ignore[ST_TEST][(unsigned int)'['] = 0;
	ignore[ST_KEY][(unsigned int)'['] = 1;

	ignore[ST_NAME][(unsigned int)'.'] = 1;
	ignore[ST_TEST][(unsigned int)'.'] = 0;
	ignore[ST_KEY][(unsigned int)'.'] = 1;
}



int pv_parse_json_name (pv_spec_p sp, const str *in)
{
	json_name * id;
	char * cur,* start;
	int state,next_state,prev_state;

	if( !inited )
		init_matrix();


	id = (json_name *) pkg_malloc(sizeof(json_name));
	if( id == NULL )
	{
		LM_ERR("Out of memory\n");
		return -1;
	}
	memset(id, 0, sizeof *id);

	id->end = &id->tags;


	state = ST_NAME;
	start = in->s;
	prev_state = -1;

	for( cur = in->s; cur < in->s + in->len; cur++)
	{
		next_state = next[state][(unsigned int)*cur];

		if( next_state == ST_ERR)
		{
			LM_ERR("Unexpected char at position: %d in :(%.*s)\n",
				(int)(cur-in->s),in->len,in->s);
			return -1;
		}

		if( state != prev_state)
			start = cur;

		if( state != next_state)
			if ( get_value(state, id, start, cur) )
				return -1;


		if( ignore[state][(unsigned int)*cur])
		{
			cur --;
		}

		prev_state = state;
		state = next_state;

	}

	if( state == ST_IDX)
	{
		LM_ERR("Mismatched parenthesis in:(%.*s)\n",in->len,in->s);
		return -1;
	}


	if( get_value(state, id, start, cur) )
		return -1;

	sp->pvp.pvn.u.dname = id ;

	return 0;
}

static int pv_parse_json_index(pv_spec_p sp, const str *in)
{
	if (in == NULL || in->s == NULL || sp == NULL)
		return -1;

	if (*in->s == '*' && in->len == 1) {
		sp->pvp.pvi.type = PV_IDX_ALL;
		return 0;
	} else {
		LM_ERR("The only index supported is \"[*]\" in for each statements\n");
		return -1;
	}
}

int mod_init(void)
{
	return 0;
}

int child_init(int rank)
{
	return 0;
}

void mod_destroy(void)
{

}

int w_merge_json(struct sip_msg *msg, str *j1, str* j2, pv_spec_t *res)
{
	cJSON *in1, *in2, *out;
	char *p;
	pv_value_t pv_val;

	in1 = cJSON_Parse(j1->s);
	if (!in1) {
		LM_ERR("Failed to parse first param \n");
		return -1;
	}

	in2 = cJSON_Parse(j2->s);
	if (!in2) {
		LM_ERR("Failed to parse second param \n");
		cJSON_Delete(in1);
		return -1;
	}

	out = cJSONUtils_MergePatch(in1,in2);
	if (!out) {
		LM_ERR("Failed to merge the two jsons \n");
		cJSON_Delete(in1);
		cJSON_Delete(in2);
		return -1;
	}

	p = cJSON_Print(out);
	if (!p) {
		LM_ERR("Failed to merge the two jsons \n");
		cJSON_Delete(in1);
		cJSON_Delete(in2);
		return -1;
	}

	cJSON_Minify(p);

	pv_val.flags = PV_VAL_STR;
	pv_val.rs.s = p;
	pv_val.rs.len = strlen(p);


	if (pv_set_value( msg, res, 0, &pv_val) != 0) {
		LM_ERR("SET output value failed \n");
		pkg_free(p);
		cJSON_Delete(in1);
		cJSON_Delete(in2);
		return -1;
	}

	pkg_free(p);
	cJSON_Delete(in1);
	cJSON_Delete(in2);

	return 1;
}
