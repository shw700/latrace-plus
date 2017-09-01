/*
  Copyright (C) 2008, 2009, 2010 Jiri Olsa <olsajiri@gmail.com>

  This file is part of the latrace.

  The latrace is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  The latrace is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with the latrace (file COPYING).  If not, see 
  <http://www.gnu.org/licenses/>.
*/

%name-prefix "lt_args_"

%{

#define YYERROR_VERBOSE 1
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "lib-include.h"

int lt_args_lex(void);
void lt_args_error(const char *m);

extern struct lt_enum *getenum(struct lt_config_shared *cfg, char *name);
extern struct lt_bm_enum *getbmenum(struct lt_config_shared *cfg, char *name);
extern struct lt_arg* find_arg(struct lt_config_shared *cfg, const char *type,
				struct lt_arg argsdef[], int size, int create);

extern struct lt_arg args_def_pod[LT_ARGS_DEF_POD_NUM];


static struct lt_config_shared *scfg;
static int struct_alive = 0;
static int struct_empty = 1;
struct lt_include *lt_args_sinc;

const char *typedef_mapping_table[11][2] =
{
	{ "unsigned long long", "u_llong" },
	{ "signed long long", "llong" },
	{ "unsigned long", "u_long" },
	{ "signed long", "long" },
	{ "long int", "long" },
	{ "unsigned int", "u_int" },
	{ "signed int", "int" },
	{ "unsigned short", "u_short" },
	{ "signed short", "short" },
	{ "unsigned char", "u_char" },
	{ "signed char", "char" },
};

#define ERROR(fmt, args...) \
do { \
	char ebuf[1024]; \
	sprintf(ebuf, fmt, ## args); \
	lt_args_error(ebuf); \
	YYERROR; \
} while(0)

#define CHK_TYPEDEF(ret, base, new, pointer) \
do { \
	switch(ret) { \
	case -1: \
		ERROR("unknown typedef - %s%s%s\n", base, (pointer ? "* " : " "), new); \
		break; \
	case  1: \
		ERROR("typedef already defined - %s%s%s\n", base, (pointer ? "* " : " "), new); \
		break; \
	case  2: \
		ERROR("typedef limit reached(%d) - %s%s%s\n", \
		         LT_ARGS_DEF_TYPEDEF_NUM, base, (pointer ? "* " : " "), new); \
		break; \
	}; \
} while(0)

#define GET_LIST_HEAD(head) \
do { \
 	if (NULL == (head = (struct lt_list_head*) malloc(sizeof(*head)))) \
		ERROR("failed to allocate list head"); \
	lt_init_list_head(head); \
} while(0)

%}


%token NAME FILENAME STRUCT ENUM BM_ENUM BM_ENUMX TYPEDEF INCLUDE END POINTER ATTRIBUTE

%union
{
	char *s;
	struct lt_arg *arg;
	struct lt_enum_elem *enum_elem;
	struct lt_bm_enum_elem *bm_enum_elem;
	struct lt_list_head *head;
}

%type <s>         NAME
%type <s>         POINTER
%type <s>         FILENAME
%type <head>      STRUCT_DEF
%type <head>      ENUM_DEF
%type <s>         ENUM_REF
%type <enum_elem> ENUM_ELEM
%type <head>      BM_ENUM_DEF
/*%type <s>         BM_ENUM_REF */
%type <bm_enum_elem> BM_ENUM_ELEM
%type <head>      ARGS
%type <arg>       DEF

%%
entry: 
entry struct_def
|
entry enum_def
| 
entry bm_enum_def
|
entry func_def
|
entry type_def
|
entry include_def
|
entry END
{
	if (lt_inc_close(scfg, lt_args_sinc))
		return 0;
}
|
/* left blank intentionally */

/* struct definitions */
struct_def:
STRUCT NAME '{' STRUCT_DEF '}' ';'
{
	int ret;

	if (struct_empty)
		ret = lt_args_add_struct(scfg, $2, NULL);
	else
		ret = lt_args_add_struct(scfg, $2, $4);

	struct_empty = 1;

	switch(ret) {
	case -1:
		ERROR("failed to add struct %s\n", $2);
	case 1:
		ERROR("struct limit reached(%d) - %s\n", LT_ARGS_DEF_STRUCT_NUM, $2);
	};

	/* force creation of the new list head */
	struct_alive = 0;
}

STRUCT_DEF:
STRUCT_DEF DEF ';'
{
	struct lt_arg *def     = $2;
	struct lt_list_head *h = $1;

	if (!struct_alive++)
		GET_LIST_HEAD(h);

	lt_list_add_tail(&def->args_list, h);
	$$ = h;
	struct_empty = 0;
}
| /* left blank intentionally,
     XXX this could be done like the args_def, but user needs to be 
     able to create an empty structure, so thats why we play 
     with the global struct_alive thingie... 
     there could be better way probably */
{
}

/* enum definitions */
enum_def:
BM_ENUMX NAME '{' ENUM_DEF '}' ';'
{
	switch(lt_args_add_enum(scfg, $2, 1, $4)) {
	case -1:
		ERROR("failed to add enum[1] %s\n", $2);
	case 1:
		ERROR("enum limit reached(%d) - %s\n", LT_ARGS_DEF_STRUCT_NUM, $2);
	};
}
|
ENUM NAME '{' ENUM_DEF '}' ';'
{
	switch(lt_args_add_enum(scfg, $2, 0, $4)) {
	case -1:
		ERROR("failed to add enum[1] %s\n", $2);
	case 1:
		ERROR("enum limit reached(%d) - %s\n", LT_ARGS_DEF_STRUCT_NUM, $2);
	};
}

ENUM_DEF:
ENUM_DEF ',' ENUM_ELEM
{
	struct lt_enum_elem *enum_elem = $3;
	struct lt_list_head *h = $1;

	lt_list_add_tail(&enum_elem->list, h);
	$$ = h;
}
| ENUM_ELEM
{
	struct lt_list_head *h;
	struct lt_enum_elem *enum_elem = $1;

	GET_LIST_HEAD(h);
	lt_list_add_tail(&enum_elem->list, h);
	$$ = h;
}

ENUM_ELEM:
NAME '=' NAME
{
	if (NULL == ($$ = lt_args_get_enum(scfg, $1, $3)))
		ERROR("failed to add enum[2] '%s = %s'\n", $1, $3);
}
|
NAME
{
	if (NULL == ($$ = lt_args_get_enum(scfg, $1, NULL)))
		ERROR("failed to add enum[3] '%s = undef'\n", $1);
}
| EMPTY_COMMA
{
}


EMPTY_COMMA:
 /* empty */


/* bitmasked enum definitions */
bm_enum_def:
BM_ENUM NAME '{' BM_ENUM_DEF '}' ';'
{
	switch(lt_args_add_bm_enum(scfg, $2, $4)) {
	case -1:
		ERROR("failed to add bm_enum[1] %s\n", $2);
	case 1:
		ERROR("bm_enum limit reached(%d) - %s\n", LT_ARGS_DEF_STRUCT_NUM, $2);
	};
}

BM_ENUM_DEF:
BM_ENUM_DEF ',' BM_ENUM_ELEM
{
	struct lt_bm_enum_elem *bm_enum_elem = $3;
	struct lt_list_head *h = $1;

	lt_list_add_tail(&bm_enum_elem->list, h);
	$$ = h;
}
| BM_ENUM_ELEM
{
	struct lt_list_head *h;
	struct lt_bm_enum_elem *bm_enum_elem = $1;

	GET_LIST_HEAD(h);
	lt_list_add_tail(&bm_enum_elem->list, h);
	$$ = h;
}

BM_ENUM_ELEM:
NAME '=' NAME
{
	if (NULL == ($$ = lt_args_get_bm_enum(scfg, $1, $3)))
		ERROR("failed to add bm_enum[2] '%s = %s'\n", $1, $3);
}

type_def:
TYPEDEF NAME NAME ';'
{
	int ret = lt_args_add_typedef(scfg, $2, $3, 0);
	CHK_TYPEDEF(ret, $2, $3, 0);
}
|
TYPEDEF NAME NAME NAME ';'
{
	char *tokname;
	size_t toklen, i;
	int found = 0;

	toklen = strlen($2) + strlen($3) + 2;
	tokname = alloca(toklen);
	memset(tokname, 0, toklen);
	snprintf(tokname, toklen, "%s %s", $2, $3);

	for (i = 0; i < sizeof(typedef_mapping_table)/sizeof(typedef_mapping_table[0]); i++) {
		if (!strcmp(typedef_mapping_table[i][0], tokname)) {
			int ret = lt_args_add_typedef(scfg, typedef_mapping_table[i][1], $4, 0);
			CHK_TYPEDEF(ret, typedef_mapping_table[i][1], $4, 0);
			found = 1;
			break;
		}
	}

	if (!found)
		ERROR("unknown complex typedef - %s\n", tokname);

}
|
TYPEDEF NAME POINTER NAME ';'
{
	int ret;
	int ptrno = strlen($3);

	free($3);
	ret = lt_args_add_typedef(scfg, $2, $4, ptrno);
	CHK_TYPEDEF(ret, $2, $4, 1);
}

/* function definitions */
func_def:
DEF '(' ARGS ')' ';'
{
	struct lt_arg *arg = $1;

	if (lt_args_add_sym(scfg, arg, $3, arg->collapsed))
		ERROR("failed to add symbol %s\n", arg->name);

	/* force creation of the new list head */
	$3 = NULL;
}
|
DEF '(' ARGS ')' ATTRIBUTE ';'
{
	struct lt_arg *arg = $1;

	if (lt_args_add_sym(scfg, arg, $3, arg->collapsed))
		ERROR("failed to add symbol %s\n", arg->name);

	/* force creation of the new list head */
	$3 = NULL;
}

ARGS:
ARGS ',' DEF
{
	struct lt_arg *def     = $3;
	struct lt_list_head *h = $1;

	lt_list_add_tail(&def->args_list, h);
	$$ = h;
}
| DEF
{
	struct lt_list_head *h;
	struct lt_arg *def = $1;

	GET_LIST_HEAD(h);
	lt_list_add_tail(&def->args_list, h);
	$$ = h;
}
| NAME
{

	if (!getenum(scfg, $1)) {
		if (find_arg(scfg, $1, args_def_pod, LT_ARGS_DEF_POD_NUM, 0) == NULL)
	                ERROR("unnamed variable of unknown type: %s\n", $1);

		GET_LIST_HEAD($$);
	} else {
		struct lt_list_head *h;
		struct lt_arg *arg = NULL;

		if (NULL == (arg = lt_args_getarg(scfg, "int", ANON_PREFIX, 0, 1, $1)))
			ERROR("unknown error parsing anonymous enum instance of type: %s\n", $1);

		GET_LIST_HEAD(h);
		lt_list_add_tail(&arg->args_list, h);
		$$ = h;
	}

}
| /* left intentionally blank */
{
	GET_LIST_HEAD($$);
}

DEF:
NAME NAME NAME ENUM_REF
{
	struct lt_arg *arg = NULL;
	char *tokname;
	size_t toklen, i;

	toklen = strlen($1) + strlen($2) + 2;
	tokname = alloca(toklen);
	memset(tokname, 0, toklen);
	snprintf(tokname, toklen, "%s %s", $1, $2);

	for (i = 0; i < sizeof(typedef_mapping_table)/sizeof(typedef_mapping_table[0]); i++) {
		if (!strcmp(typedef_mapping_table[i][0], tokname)) {
			arg = lt_args_getarg(scfg, typedef_mapping_table[i][1], $3, 0, 1, $4);
			break;
		}
	}

	if (!arg)
                ERROR("unknown argument type[1] - %s\n", $1);

	$$ = arg;
}
| NAME NAME POINTER NAME
{
	struct lt_arg *arg = NULL;
	char *tokname;
	size_t toklen, i;
	int ptrno = strlen($3);

	free($3);
	toklen = strlen($1) + strlen($2) + 2;
	tokname = alloca(toklen);
	memset(tokname, 0, toklen);
	snprintf(tokname, toklen, "%s %s", $1, $2);

	for (i = 0; i < sizeof(typedef_mapping_table)/sizeof(typedef_mapping_table[0]); i++) {
		if (!strcmp(typedef_mapping_table[i][0], tokname)) {
			arg = lt_args_getarg(scfg, typedef_mapping_table[i][1], $4, ptrno, 1, NULL);
			break;
		}
	}

	if (!arg)
                ERROR("unknown argument type[10] - %s\n", $1);

	$$ = arg;
}
|
NAME NAME ENUM_REF
{
	struct lt_arg *arg;

	if (NULL == (arg = lt_args_getarg(scfg, $1, $2, 0, 1, $3))) {
		if (getenum(scfg, $1) == NULL) {
			if (getbmenum(scfg, $1) == NULL)
				ERROR("unknown argument type[2a] - %s; possibly due to enum specification of \"%s\"\n", $1, $3);
		}

		if (NULL == (arg = lt_args_getarg(scfg, "int", $2, 0, 1, $1)))
			ERROR("unknown argument type[2b] - %s; possibly due to enum specification of \"%s\"\n", $1, $3);
	}

	$$ = arg;
}
|
NAME POINTER NAME ENUM_REF
{
	struct lt_arg *arg;
	int ptrno = strlen($2);

	free($2);

	if (NULL == (arg = lt_args_getarg(scfg, $1, $3, ptrno, 1, $4))) {
		if (NULL == (arg = lt_args_getarg(scfg, "void", $3, ptrno, 1, $4)))
			ERROR("unknown argument type[3] - %s\n", $1);
	}

	$$ = arg;
}
|
STRUCT NAME NAME
{
	struct lt_arg *arg;

	if (NULL == (arg = lt_args_getarg(scfg, $2, $3, 0, 1, NULL)))
		ERROR("unknown argument type[4] - %s\n", $2);

	$$ = arg;
}
|
STRUCT NAME POINTER NAME ENUM_REF
{
	struct lt_arg *arg;
	int ptrno = strlen($3);

	free($3);

	if (NULL == (arg = lt_args_getarg(scfg, $2, $4, ptrno, 1, $5))) {
		if (NULL == (arg = lt_args_getarg(scfg, "void", $4, ptrno, 1, $5)))
			ERROR("unknown argument type[5] - %s\n", $2);
	}

	$$ = arg;
}
|
NAME
{
	struct lt_arg *arg;

	if (NULL == (arg = lt_args_getarg(scfg, $1, ANON_PREFIX, 0, 1, NULL))) {

		if (getenum(scfg, $1) == NULL)
			ERROR("unknown argument type[6a] - %s\n", $1);

		if (NULL == (arg = lt_args_getarg(scfg, "int", ANON_PREFIX, 0, 1, $1)))
			ERROR("unknown argument type[6b] - %s\n", $1);

	}

	$$ = arg;
}
|
NAME POINTER
{
	struct lt_arg *arg;
	int ptrno = strlen($2);

	free ($2);

	if (NULL == (arg = lt_args_getarg(scfg, $1, ANON_PREFIX, ptrno, 1, NULL))) {
		if (NULL == (arg = lt_args_getarg(scfg, "void", ANON_PREFIX, ptrno, 1, NULL)))
			ERROR("unknown argument type[7] - %s\n", $1);
	}

	$$ = arg;
}
|
STRUCT NAME POINTER
{
	struct lt_arg *arg;
	int ptrno = strlen($3);

	free($3);

	if (NULL == (arg = lt_args_getarg(scfg, $2, ANON_PREFIX, ptrno, 1, NULL))) {
		if (NULL == (arg = lt_args_getarg(scfg, "void", ANON_PREFIX, ptrno, 1, NULL)))
			ERROR("unknown argument type[8] - %s\n", $2);
	}

	$$ = arg;
}
|
NAME '=' NAME NAME
{
	struct lt_arg *arg;

	if (NULL == (arg = lt_args_getarg(scfg, $1, $4, 0, 1, $3)))
		ERROR("unknown argument type[9] - %s; possibly due to enum specification of \"%s\"\n", $1, $3);

	$$ = arg;
}

ENUM_REF:
'=' NAME
{
	$$ = $2;
}
| 
{
	$$ = NULL;
}

/* include definitions */
include_def: INCLUDE '"' FILENAME '"'
{
	if (lt_inc_open(scfg, lt_args_sinc, $3))
		ERROR("failed to process include");
}

%%

int lt_args_parse_init(struct lt_config_shared *cfg, struct lt_include *inc)
{
	scfg = cfg;
	lt_args_sinc = inc;
	return 0;
}
