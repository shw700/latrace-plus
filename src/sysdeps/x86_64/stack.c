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


#include "config.h"
#include "stack.h"
#include <stdlib.h>


#define ASS_CLEANUP() \
do { \
	tsd->ass_integer = tsd->ass_sse = tsd->ass_memory = 0; \
} while(0)

/* INTEGER registers used for function arguments. */
static long ass_regs_integer[] = {
	LT_64_REG_RDI,
	LT_64_REG_RSI,
	LT_64_REG_RDX,
	LT_64_REG_RCX,
	LT_64_REG_R8,
	LT_64_REG_R9,
};
#define ASS_REGS_INTEGER_CNT  (sizeof(ass_regs_integer)/sizeof(long))
#define ASS_REGS_INTEGER_SIZE (sizeof(ass_regs_integer))

/* INTEGER registers used for function return arguments. */
static long ass_regs_integer_ret[] = {
	LT_64_REG_RAX,
	LT_64_REG_RDX,
};
#define ASS_REGS_INTEGER_RET_CNT  (sizeof(ass_regs_integer_ret)/sizeof(long))
#define ASS_REGS_INTEGER_RET_SIZE (sizeof(ass_regs_integer_ret))

/* SSE registers used for function arguments. */
static long ass_regs_sse[] = {
	LT_64_REG_XMM0,
	LT_64_REG_XMM1,
	LT_64_REG_XMM2,
	LT_64_REG_XMM3,
	LT_64_REG_XMM4,
	LT_64_REG_XMM5,
	LT_64_REG_XMM6,
	LT_64_REG_XMM7,
};
#define ASS_REGS_SSE_CNT  (sizeof(ass_regs_sse)/sizeof(long))

/* SSE registers used for function return arguments. They 
   are xmm0 and xmm1, so we reuse the ass_regs_sse array.*/
#define ASS_REGS_SSE_RET_CNT  (2)

static int classificate_arg(struct lt_config_shared *cfg, struct lt_arg *arg,
				int ret, int align, lt_tsd_t *tsd);

STATIC int classificate_memory(struct lt_config_shared *cfg,
			struct lt_arg *arg, int align, lt_tsd_t *tsd)
{

	if (align)
		tsd->ass_memory = LT_STACK_ALIGN(tsd->ass_memory);
	else {
		int naligned = tsd->ass_memory % arg->type_len;

		if (naligned)
			tsd->ass_memory += arg->type_len - naligned;
	}

	PRINT_VERBOSE(cfg, 2, "%s - ass %d\n",
			arg->name, tsd->ass_memory);

	ARCH_SET(arg, ARCH_FLAG_MEM, tsd->ass_memory);

	if (arg->pointer)
		tsd->ass_memory += sizeof(void*);
	else
		tsd->ass_memory += arg->type_len;
		
	return 0;
}

STATIC int classificate_integer(struct lt_config_shared *cfg,
			struct lt_arg *arg, int align, int regs_size,
			lt_tsd_t *tsd)
{

	if (!align) {
		int ass = LT_STACK_ALIGN(tsd->ass_integer);
		int naligned = tsd->ass_integer % arg->type_len;

		if (naligned)
			tsd->ass_integer += arg->type_len - naligned;

		if ((tsd->ass_integer + arg->type_len) > ass)
			tsd->ass_integer = LT_STACK_ALIGN(tsd->ass_integer);
	}

	PRINT_VERBOSE(cfg, 2,
			"ass %s - reg size %d - ass_integer %d\n", 
			arg->name, regs_size, tsd->ass_integer);

	if (tsd->ass_integer >= regs_size)
		return -1;

	ARCH_SET(arg, ARCH_FLAG_REG_INTEGER, tsd->ass_integer);

	if (arg->pointer)
		tsd->ass_integer += sizeof(void*);
	else
		tsd->ass_integer += align ? sizeof(void*) : arg->type_len;

	return 0;
}

STATIC int classificate_sse(struct lt_config_shared *cfg, struct lt_arg *arg,
				int sse_cnt, lt_tsd_t *tsd)
{

	PRINT_VERBOSE(cfg, 2, "ass %s %d %d\n",
			arg->name, ASS_REGS_SSE_CNT, tsd->ass_sse);

	if (sse_cnt == tsd->ass_sse)
		return -1;

	ARCH_SET(arg, ARCH_FLAG_REG_SSE, tsd->ass_sse++);
	return 0;
}

STATIC void struct_arch(struct lt_config_shared *cfg, struct lt_arg *sarg,
			struct lt_arg *farg)
{
	if (sarg->pointer)
		return;

	/* Structures passed by value dont have the arch assigned by default.
	   If the first argument is returned in memory, the structure takes
	   this pointer, if it is register, we keep it NULL, and lt_args_cb_arg
	    will print out the REG kw for value.*/
	PRINT_VERBOSE(cfg, 2,
			"first argument for struct %s has flag: %d\n", 
			sarg->name, ARCH_GET_FLAG(farg));

	if (ARCH_GET_FLAG(farg) == ARCH_FLAG_MEM)
		sarg->arch = farg->arch;
	else
		ARCH_SET(sarg, ARCH_FLAG_SVREG, 0);
}


STATIC int classificate_struct_try(struct lt_config_shared *cfg,
			struct lt_arg *arg, int allmem, int ret,
			lt_tsd_t *tsd)
{
	struct lt_arg *a;
	int first = 1;
	int saved_ass_integer = tsd->ass_integer;
	int saved_ass_sse     = tsd->ass_sse;
	int saved_ass_memory  = tsd->ass_memory;

	lt_list_for_each_entry(a, arg->args_head, args_list) {

		if (allmem)
			classificate_memory(cfg, a, first, tsd);
		else {
			if (-1 == classificate_arg(cfg, a, ret, 0, tsd))
				return -1;

			if (ARCH_GET_FLAG(arg) == ARCH_FLAG_MEM) {
				/* There is not enough registers, reset to 
				   have the structure in memory only. */
				tsd->ass_integer = saved_ass_integer;
				tsd->ass_sse     = saved_ass_sse;
				tsd->ass_memory  = saved_ass_memory;
				return -1;
			}

		}

		if (first) {
			struct_arch(cfg, arg, a);
			first = 0;
		}
	}

	return 0;
}

STATIC int get_sizeof(struct lt_config_shared *cfg, struct lt_arg *arg)
{
	struct lt_arg *a;
	int size = 0;

	lt_list_for_each_entry(a, arg->args_head, args_list) {

		int naligned = (u_int) size % a->type_len;

		if (naligned)
			size += a->type_len - naligned;

		size += a->type_len;
	}

	PRINT_VERBOSE(cfg, 2, "sizeof(struct %s) = %d\n",
		arg->type_name, size);

	return size;
}

STATIC int classificate_struct(struct lt_config_shared *cfg, struct lt_arg *arg,
				int ret, lt_tsd_t *tsd)
{
	int allmem = 0;
	int size = get_sizeof(cfg, arg);

	/* If the structure is bigger than 16B or passed as pointer then 
	   it is in the memory (no registers). If the structure is up to 
	   16B and passed by value, we might need t classificate its members,
	   because they could fit in registers. */
	if ((size > 16) || (arg->pointer))
		allmem = 1;

	PRINT_VERBOSE(cfg, 2,
		"struct %s - length sum %d - allmem %d\n", 
		arg->type_name, arg->type_len, allmem);

	if (-1 == classificate_struct_try(cfg, arg, allmem, ret, tsd))
		classificate_struct_try(cfg, arg, 1, ret, tsd);

	return 0;
}

STATIC int classificate_arg_type(struct lt_config_shared *cfg,
				struct lt_arg *arg)
{
	int class;

	do {
		/* pointers are INTEGER class by default */
		if (arg->pointer) {
			class = LT_CLASS_INTEGER;
			break;
		}

		switch(arg->type_id) {
		case LT_ARGS_TYPEID_BOOL:
		case LT_ARGS_TYPEID_CHAR:
		case LT_ARGS_TYPEID_UCHAR:
		case LT_ARGS_TYPEID_SHORT:
		case LT_ARGS_TYPEID_USHORT:
		case LT_ARGS_TYPEID_INT:
		case LT_ARGS_TYPEID_UINT:
		case LT_ARGS_TYPEID_LONG:
		case LT_ARGS_TYPEID_ULONG:
		case LT_ARGS_TYPEID_LLONG:
		case LT_ARGS_TYPEID_ULLONG:
			class = LT_CLASS_INTEGER;
			break;

		case LT_ARGS_TYPEID_DOUBLE:
		case LT_ARGS_TYPEID_FLOAT:
			class = LT_CLASS_SSE;
			break;

		default:
			class = LT_CLASS_NONE;
			break;
		}

	} while(0);

	PRINT_VERBOSE(cfg, 2,
			"argument %s dtype %d - type %s(%d) - class %d\n", 
			arg->name, arg->dtype, arg->type_name, arg->type_id, 
			class);
	return class;
}

STATIC int classificate_arg(struct lt_config_shared *cfg, struct lt_arg *arg,
				int ret, int align, lt_tsd_t *tsd)
{
	int class;
	int class_failed = 0;

	PRINT_VERBOSE(cfg, 2, "got arg \"%s\"\n",
			arg->name);

	ARCH_ZERO(arg);

	if (arg->dtype != LT_ARGS_DTYPE_POD) {

		if (-1 == classificate_struct(cfg, arg, ret, tsd))
			return -1;

		/* If the structure is passed by pointer, we 
		   still need the pointer classification. */
		if (!arg->pointer)
			return 0;
	}

	class = classificate_arg_type(cfg, arg);
	if (-1 == class)
		return -1;

	/* Nothing to be done for NONE class (void type) */
	if (LT_CLASS_NONE == class)
		return 0;

	switch(class) {
	case LT_CLASS_SSE:
		class_failed = classificate_sse(cfg, arg, 
				(ret ? ASS_REGS_SSE_RET_CNT :
				      ASS_REGS_SSE_CNT), tsd);
		break;
			
	case LT_CLASS_INTEGER:
		class_failed = classificate_integer(cfg, arg, align,
				(ret ? ASS_REGS_INTEGER_RET_SIZE :
				      ASS_REGS_INTEGER_SIZE), tsd);
		break;

	case LT_CLASS_MEMORY:
		classificate_memory(cfg, arg, 1, tsd);
		break;
	}

	/* If class INTEGER or SSE ran out of registers, 
	   then arg is in memory. */
	if (class_failed)
		classificate_memory(cfg, arg, 1, tsd);

	return 0;
}

STATIC int classificate(struct lt_config_shared *cfg, struct lt_args_sym *sym, lt_tsd_t *tsd)
{
	int i;
	struct lt_arg *arg = sym->args[LT_ARGS_RET];

	PRINT_VERBOSE(cfg, 2, "got symbol \"%s\"\n",
			sym->name);

	ASS_CLEANUP();

	/* Classificate the return value first. */
	if (-1 == classificate_arg(cfg, arg, 1, 1, tsd))
		return -1;

	ASS_CLEANUP();

	/* If the return value is memory class, 
	   then the edi register is used as a first hidden arg.*/
	if (ARCH_GET_FLAG(arg) == ARCH_FLAG_MEM)
		tsd->ass_integer += 8;

	for(i = 1; i < sym->argcnt; i++) {
		arg = sym->args[i];

		if (-1 == classificate_arg(cfg, arg, 0, 1, tsd))
			return -1;
	}

	return 0;
}

STATIC void *get_value_mem(struct lt_config_shared *cfg, struct lt_arg *arg,
			void *regs, int ret)
{
	long offset = ARCH_GET_OFFSET(arg);
	void *pval;

	if (ret) {
		void *base = (void*) ((struct La_x86_64_retval*) regs)->lrv_rax;
		pval = base + offset;
	} else {
		void *base = (void*) ((struct La_x86_64_regs*) regs)->lr_rsp;
		pval = base +            /* current stack pointer */
		       sizeof(void*) +   /* return function address */
		       offset;
	}

	PRINT_VERBOSE(cfg, 2, "offset = %ld, %s = %p, ret = %d\n",
			offset, arg->name, pval, ret);
	return pval;
}

STATIC void *get_value_reg_integer(struct lt_config_shared *cfg,
			struct lt_arg *arg, void *regs, int ret)
{
	struct La_x86_64_retval *regs_ret = regs;
	struct La_x86_64_regs   *regs_in  = regs;
	void *pval  = NULL;
	long offset = ARCH_GET_OFFSET(arg);
	long qoff   = offset % sizeof(long);
	long reg    = ret ? ass_regs_integer_ret[offset / sizeof(long)] :
			    ass_regs_integer[offset / sizeof(long)];
			

	PRINT_VERBOSE(cfg, 2,
			"offset %ld - reg %ld - qoff %ld - ASS_REGS_CNT %ld - ret %d\n", 
			offset, reg, qoff, ASS_REGS_INTEGER_CNT, ret);

	switch(reg) {
	case LT_64_REG_RAX:
		pval = &regs_ret->lrv_rax;
		break;
	case LT_64_REG_RDX:
		pval = ret ? &regs_ret->lrv_rdx : &regs_in->lr_rdx;
		break;
	case LT_64_REG_RDI:
		pval = &regs_in->lr_rdi;
		break;
	case LT_64_REG_RSI:
		pval = &regs_in->lr_rsi;
		break;
	case LT_64_REG_RCX:
		pval = &regs_in->lr_rcx;
		break;
	case LT_64_REG_R8:
		pval = &regs_in->lr_r8;
		break;
	case LT_64_REG_R9:
		pval = &regs_in->lr_r9;
		break;
	}

	pval += qoff;

	PRINT_VERBOSE(cfg, 2, "argument %s = %p (%lx)\n",
			arg->name, pval, *((u_long*)pval));
	return pval;
}

STATIC void *get_value_reg_sse(struct lt_config_shared *cfg,
			struct lt_arg *arg, void *regs, int ret)
{
	int i = ARCH_GET_OFFSET(arg);
	void *pval = NULL;

	if (ret) {
		struct La_x86_64_retval *regs_ret = regs;

		switch(i) {
		case 0: 
			pval = &regs_ret->lrv_xmm0; 
			break;
		case 1: 
			pval = &regs_ret->lrv_xmm1; 
			break;
		}
	} else {
		struct La_x86_64_regs *regs_in = regs;

		pval = &regs_in->lr_xmm[i];
	}


	PRINT_VERBOSE(cfg, 2, "argument %s = %p (%lx), ret %d\n",
			arg->name, pval, *((u_long*)pval), ret);
	return pval;
}

STATIC void* get_value(struct lt_config_shared *cfg, struct lt_arg *arg,
			void *regs, int ret)
{
	void *pval = NULL;

	PRINT_VERBOSE(cfg, 2, "get value for %s - arch = %lx, flag = %d\n",
			arg->name, ARCH_GET(arg), ARCH_GET_FLAG(arg));

	switch(ARCH_GET_FLAG(arg)) {
	case ARCH_FLAG_MEM:
		pval = get_value_mem(cfg, arg, regs, ret);
		break;

	case ARCH_FLAG_REG_INTEGER:
		pval = get_value_reg_integer(cfg, arg, regs, ret);
		break;

	case ARCH_FLAG_REG_SSE:
		pval = get_value_reg_sse(cfg, arg, regs, ret);
		break;
	}

	return pval;
}

/* Process structure stored completelly in the 
   memory - pointed to by 'pval' arg. */
STATIC int process_struct_mem(struct lt_config_shared *cfg, struct lt_arg *arg,
				void *pval, struct lt_args_data *data, lt_tsd_t *tsd)
{
	struct lt_arg *a;
	int i = 0;

	PRINT_VERBOSE(cfg, 2, "for %s - arch = %llx\n",
			arg->name, ARCH_GET(arg));

	lt_args_cb_struct(cfg, LT_ARGS_STRUCT_ITSELF, arg, NULL, data, 0, tsd);

	lt_list_for_each_entry(a, arg->args_head, args_list) {
		int last = (i + 1) == arg->mmbcnt;
		void *pv = pval + ARCH_GET_OFFSET(a);

		lt_args_cb_struct(cfg, LT_ARGS_STRUCT_ARG, a, pv, data, last, tsd);

		i++;
	}

	return 0;
}

STATIC int process_struct_arg(struct lt_config_shared *cfg, struct lt_arg *arg,
			void *regs, struct lt_args_data *data, int ret, lt_tsd_t *tsd)
{
	struct lt_arg *a;
	int i = 0;

	PRINT_VERBOSE(cfg, 2, "for %s - arch = %llx\n",
			arg->name, ARCH_GET(arg));

	lt_args_cb_struct(cfg, LT_ARGS_STRUCT_ITSELF, arg, NULL, data, 0, tsd);

	lt_list_for_each_entry(a, arg->args_head, args_list) {
		int last = (i + 1) == arg->mmbcnt;
		void *pval = NULL;

		pval = get_value(cfg, a, regs, ret);

		lt_args_cb_struct(cfg, LT_ARGS_STRUCT_ARG, a, pval, data, last, tsd);
		i++;
	}

	return 0;
}

STATIC void process_detailed_struct(struct lt_config_shared *cfg,
		struct lt_arg *arg, void *pval, struct lt_args_data *data, 
		void *regs, int ret, lt_tsd_t *tsd)
{
	if (arg->pointer)
		pval = *((void**) pval);

	if (ARCH_GET_FLAG(arg) == ARCH_FLAG_MEM) {
		process_struct_mem(cfg, arg, pval, data, tsd);
	} else {
		if (arg->pointer)
			process_struct_mem(cfg, arg, pval, data, tsd);
		else
			process_struct_arg(cfg, arg, regs, data, ret, tsd);
	}
}

STATIC void
enter_transformer_callstack(char *symname, La_regs *inregs, void **args, size_t argcnt, lt_tsd_t *tsd)
{

	if (!tsd->xfm_call_stack_max)
	{
		tsd->xfm_call_stack_max = 8;
		tsd->xfm_call_stack_sz = 0;
#ifdef USE_GLIBC_FEATURES
		XMALLOC_ASSIGN(tsd->xfm_call_stack, (sizeof(*tsd->xfm_call_stack) * tsd->xfm_call_stack_max));
#else
		tsd->xfm_call_stack = safe_malloc(sizeof(*tsd->xfm_call_stack) * tsd->xfm_call_stack_max);
#endif
	} else if (tsd->xfm_call_stack_sz == tsd->xfm_call_stack_max) {
		size_t new_size;

		tsd->xfm_call_stack_max *= 2;
		new_size = sizeof(*tsd->xfm_call_stack) * tsd->xfm_call_stack_max;
#ifdef USE_GLIBC_FEATURES
		XREALLOC_ASSIGN(tsd->xfm_call_stack, tsd->xfm_call_stack, new_size);
#else
		tsd->xfm_call_stack = safe_realloc(tsd->xfm_call_stack, new_size);
#endif
	}

	if (!tsd->xfm_call_stack) {
		PERROR("Error allocating space for call stack");
		return;
	}

	tsd->xfm_call_stack[tsd->xfm_call_stack_sz].fn_name = symname;
	tsd->xfm_call_stack[tsd->xfm_call_stack_sz].args = args;
	tsd->xfm_call_stack[tsd->xfm_call_stack_sz].argcnt = argcnt;
	memcpy(&tsd->xfm_call_stack[tsd->xfm_call_stack_sz].registers, inregs, sizeof(*inregs));
	tsd->xfm_call_stack_sz++;

	return;
}

STATIC int
exit_transformer_callstack(char *symname, La_regs *inregs, void ***pargs, size_t *pargcnt, lt_tsd_t *tsd)
{
	int i;

	if (!tsd->xfm_call_stack_max || !tsd->xfm_call_stack_sz) {
		PRINT_ERROR_SAFE("%s", "Whoops: could not find entry on transformer call stack.\n");
		return -1;
	}

	for (i = tsd->xfm_call_stack_sz; i > 0; i--) {

		if (strcmp(tsd->xfm_call_stack[i-1].fn_name, symname))
			continue;

		if (memcmp(&(tsd->xfm_call_stack[i-1].registers), inregs, sizeof(*inregs)))
			continue;

		*pargs = tsd->xfm_call_stack[i-1].args;
		*pargcnt = tsd->xfm_call_stack[i-1].argcnt;

		memcpy(&(tsd->xfm_call_stack[i-1]), &(tsd->xfm_call_stack[i]),
			(sizeof(fn_call_t) * (tsd->xfm_call_stack_sz - i)));

		tsd->xfm_call_stack_sz--;
		return 0;
	}

	return -1;
}

STATIC int func_has_inargs(struct lt_args_sym *asym)
{
	size_t i;

	for (i = 1; i < asym->argcnt; i++) {

		// Input/output arguments are only applicable if pointers
		if (asym->args[i]->fmt && (asym->args[i]->pointer > 0) &&
			(strchr(asym->args[i]->fmt, 'r') || strchr(asym->args[i]->fmt, 'R')))
			return 1;
	}

	return 0;
}

#ifdef TRANSFORMER_CRASH_PROTECTION
	#define CRASH_PROLOGUE(x)	 do { if (tsd) { tsd->jmp_set = (sigsetjmp(tsd->crash_insurance, 1) == 0) ? x : 0; } } while (0)
	#define CRASH_EPILOGUE(x)	 TSD_SET(jmp_set,0)
#else
	#define CRASH_PROLOGUE(x)	;
	#define CRASH_EPILOGUE(x)	;
#endif

int lt_stack_process(struct lt_config_shared *cfg, struct lt_args_sym *asym, 
			La_regs *regs, struct lt_args_data *data, int silent,
			lt_tsd_t *tsd)
{
	int i;

	if (asym->args[LT_ARGS_RET]->latrace_custom_func_transformer ||
			asym->args[LT_ARGS_RET]->latrace_custom_func_intercept ||
			func_has_inargs(asym)) {
		void **targs;
		int tres = -1;

		if (!ARCH_GET(asym->args[LT_ARGS_RET]) &&
		    (-1 == classificate(cfg, asym, tsd)))
			return -1;
#ifdef USE_GLIBC_FEATURES
		XMALLOC_ASSIGN(targs, (sizeof(void *) * asym->argcnt));
#else
		targs = safe_malloc((sizeof(void *) * asym->argcnt));
#endif

		if (!targs)
			return -1;

		for(i = 1; i < asym->argcnt; i++) {
			void *pval = NULL;
			struct lt_arg *arg = asym->args[i];

			pval = get_value(cfg, arg, regs, 0);
			targs[i-1] = pval;
		}

		if (asym->args[LT_ARGS_RET]->latrace_custom_func_intercept) {
			CRASH_PROLOGUE(CODE_LOC_LA_INTERCEPT);
			if (tsd->fault_reason) {
				PRINT_ERROR("Error: caught fatal condition in custom func intercept entry for %s: %s\n",
					asym->name, tsd->fault_reason);
				tsd->fault_reason = NULL;
			} else
				asym->args[LT_ARGS_RET]->latrace_custom_func_intercept(targs, asym->argcnt-1, NULL);

			CRASH_EPILOGUE();
		}

		if (!silent && asym->args[LT_ARGS_RET]->latrace_custom_func_transformer) {
			CRASH_PROLOGUE(CODE_LOC_LA_TRANSFORMER);

			if (tsd->fault_reason) {
				PRINT_ERROR("Error: caught fatal condition in custom func transformer entry for %s: %s\n",
					asym->name, tsd->fault_reason);
				tsd->fault_reason = NULL;
			} else {
				tres = asym->args[LT_ARGS_RET]->latrace_custom_func_transformer(targs,
					asym->argcnt-1, data->args_buf+data->args_totlen, data->args_len-data->args_totlen, NULL);
			}

			CRASH_EPILOGUE();
		}

/*		if (silent) {
			XFREE(targs);
			return 0;
		} */

		enter_transformer_callstack(asym->name, regs, targs, asym->argcnt-1, tsd);

		if (silent)
			return 0;

		if (!tres) {
			data->args_totlen += strlen(data->args_buf+data->args_totlen);
			return tres;
		}

	}

	if (!ARCH_GET(asym->args[LT_ARGS_RET]) &&
	    (-1 == classificate(cfg, asym, tsd)))
		return -1;

	if (asym->argcnt == 1) {
		snprintf(data->args_buf+data->args_totlen, data->args_len-data->args_totlen, "void");
		data->args_totlen += strlen(data->args_buf+data->args_totlen);
		return 0;
	}

	for(i = 1; i < asym->argcnt; i++) {
		void *pval = NULL;
		struct lt_arg *arg = asym->args[i];
		int last = (i + 1) == asym->argcnt;

		pval = get_value(cfg, arg, regs, 0);

		if (pval && arg->latrace_custom_struct_transformer && (!arg->fmt || !*(arg->fmt))) {
			void *pvald = *((void**) pval);
			size_t left, saved_totlen;
			int result;
			static size_t seplen_color = 0;

			if (!seplen_color)
				seplen_color = strlen(BOLD) + strlen(BOLDOFF) + 2;

			saved_totlen = data->args_totlen;
//			left = data->arglen - data->args_totlen;
			if ((i * data->arglen) < data->args_len)
				left = (i * data->arglen) - data->args_totlen;
			else
				left = data->args_len - data->args_totlen;

			memset(data->args_buf+data->args_totlen, 0, left);
			left--;
			result = snprintf(data->args_buf+data->args_totlen, left, "%s = ", arg->name);
			data->args_totlen += result;
			left -= result;

			if (i+1 < asym->argcnt)
				left -= (cfg->fmt_colors ? seplen_color : 2);

			CRASH_PROLOGUE(CODE_LOC_LA_TRANSFORMER);

			if (tsd->fault_reason) {
				fprintf(stderr, "Error: caught fatal condition in custom func transformer entry for %s: %s\n",
					asym->name, tsd->fault_reason);
				tsd->fault_reason = NULL;
				CRASH_EPILOGUE();
			} else {
				result = arg->latrace_custom_struct_transformer(pvald, data->args_buf+data->args_totlen, left);
				CRASH_EPILOGUE();

				if (!result) {
					data->args_totlen += strlen(data->args_buf+data->args_totlen);

					if (i+1 < asym->argcnt) {
						char fmtbuf[16];
						size_t max_append;

						if (cfg->fmt_colors)
							snprintf(fmtbuf, sizeof(fmtbuf), "%s, %s", BOLD, BOLDOFF);
						else
							strcpy(fmtbuf, ", ");

						max_append = data->args_len - data->args_totlen;
						max_append = strlen(fmtbuf) > max_append ? max_append : strlen(fmtbuf);
						strncat(data->args_buf+data->args_totlen, fmtbuf, max_append);
						data->args_totlen += max_append;
					}

					continue;
				} else {
					data->args_totlen = saved_totlen;
					memset(data->args_buf+data->args_totlen, 0, left);
				}

			}

		}

		if ((!pval) && 
		    (arg->pointer || ((LT_ARGS_DTYPE_STRUCT != arg->dtype) &&
		    (arg->type_id != LT_ARGS_TYPEID_VARARG) && (arg->type_id != LT_ARGS_TYPEID_FNPTR)))) {
			PRINT_VERBOSE(cfg, 2,
				"THIS SHOULD NEVER HAPPEN - arg '%s %s'\n",
				arg->type_name, arg->name);
			continue;
		}

		lt_args_cb_arg(cfg, arg, pval, data, last, 1, tsd);

		if ((cfg->args_detailed) && 
		    (LT_ARGS_DTYPE_STRUCT == arg->dtype))
			process_detailed_struct(cfg, arg, pval, data, regs, 0, tsd);
	}

	return 0;
}

int lt_stack_process_ret(struct lt_config_shared *cfg, struct lt_args_sym *asym,
			La_regs *iregs, La_retval *regs, struct lt_args_data *data, int silent,
			lt_tsd_t *tsd)
{
	struct lt_arg *arg;
	void *pval;
	int needs_callstack = 0, has_ret_inargs = 0;
	size_t i;

	arg = asym->args[LT_ARGS_RET];
	pval = get_value(cfg, arg, regs, 1);
	needs_callstack = ((asym->args[LT_ARGS_RET]->latrace_custom_func_transformer != NULL) ||
		(asym->args[LT_ARGS_RET]->latrace_custom_func_intercept != NULL));

	if (func_has_inargs(asym))
		needs_callstack = has_ret_inargs = 1;

	if (needs_callstack || has_ret_inargs || asym->args[LT_ARGS_RET]->latrace_custom_struct_transformer) {
		void **inargs = NULL;
		void *retval = pval;
		size_t inargs_size = 0;
		int tres = -1;

//		if (!silent && exit_transformer_callstack(asym->name, iregs, &inargs, &inargs_size, tsd) < 0) {
		if ((needs_callstack || has_ret_inargs) &&
				(exit_transformer_callstack(asym->name, iregs, &inargs, &inargs_size, tsd) < 0)) {
			PRINT_ERROR_SAFE("%s", "Error retrieving function entry arguments from transformer call stack\n");
			inargs = NULL;
			inargs_size = 0;
		}

		/* Special null value for functions that are declared to return type void */
		retval = !retval ? (void *)-1 : retval;

		if (asym->args[LT_ARGS_RET]->latrace_custom_func_intercept) {
			CRASH_PROLOGUE(CODE_LOC_LA_INTERCEPT);

			if (tsd->fault_reason) {
				fprintf(stderr, "Error: caught fatal condition in custom func intercept exit for %s: %s\n",
					asym->name, tsd->fault_reason);
				tsd->fault_reason = NULL;
			} else
				asym->args[LT_ARGS_RET]->latrace_custom_func_intercept(inargs, inargs_size, retval);

			CRASH_EPILOGUE();
		}

		if (!silent && asym->args[LT_ARGS_RET]->latrace_custom_func_transformer) {
			CRASH_PROLOGUE(CODE_LOC_LA_TRANSFORMER);

			if (tsd->fault_reason) {
				fprintf(stderr, "Error: caught fatal condition in custom func transformer exit for %s: %s\n",
					asym->name, tsd->fault_reason);
				tsd->fault_reason = NULL;
			} else {
				tres = asym->args[LT_ARGS_RET]->latrace_custom_func_transformer(inargs,
					inargs_size, data->args_buf+data->args_totlen, data->args_len-data->args_totlen, retval);
			}

			CRASH_EPILOGUE();
		}

		if (!silent && (tres < 0) && asym->args[LT_ARGS_RET]->latrace_custom_struct_transformer && pval &&
			(!asym->args[LT_ARGS_RET]->fmt || !*(asym->args[LT_ARGS_RET]->fmt))) {
			CRASH_PROLOGUE(CODE_LOC_LA_TRANSFORMER);

			if (tsd->fault_reason) {
				fprintf(stderr, "Error: caught fatal condition in custom struct transformer exit for %s: %s\n",
					asym->name, tsd->fault_reason);
				tsd->fault_reason = NULL;
			} else {
				tres = asym->args[LT_ARGS_RET]->latrace_custom_struct_transformer(*((void**) pval), data->args_buf+data->args_totlen, data->args_len-data->args_totlen);
			}

			CRASH_EPILOGUE();
		}

		// Should only be reached if we have a return arg struct transformer and NOT a function transformer,
		// or if the function transformer fails.
		if (!silent && inargs && has_ret_inargs && ((tres < 0) || (!asym->args[LT_ARGS_RET]->latrace_custom_func_transformer))) {
			size_t nleft;
			int first = 1;

			if (!tres)
				data->args_totlen += strlen(data->args_buf + data->args_totlen);

#define APPEND_ARG_STR(fmt,val)	\
	nleft = data->args_len - data->args_totlen;	\
	snprintf(data->args_buf+data->args_totlen, nleft, fmt, val);	\
	data->args_totlen += strlen(data->args_buf+data->args_totlen);	\

			APPEND_ARG_STR("%s", "{");

			for (i = 1; i < asym->argcnt; i++) {
				int trace_level = 0;

				if (asym->args[i]->fmt && (asym->args[i]->pointer > 0) && (strchr(asym->args[i]->fmt, 'r')))
					trace_level = 1;
				else if (asym->args[i]->fmt && (asym->args[i]->pointer > 0) && (strchr(asym->args[i]->fmt, 'R')))
					trace_level = 2;

				if (trace_level > 0) {
					void **argval = (void **)inargs[i-1];
					struct lt_arg arg_copy;
					char *prefix;

					prefix = first ? "%s=" : ", %s=";
					first = 0;

					APPEND_ARG_STR(prefix, asym->args[i]->name);
					memcpy(&arg_copy, asym->args[i], sizeof(struct lt_arg));

					if (trace_level == 2)
						arg_copy.fmt = "";
					else
						arg_copy.pointer--;

					// Our callback occurs on the dereferenced pointer type of the argument.
					lt_args_cb_arg(cfg, &arg_copy, *argval, data, 1, 0, tsd);
				}

			}

			APPEND_ARG_STR("%s", "} ");
		}


		if (inargs)
#ifdef USE_GLIBC_FEATURES
			XFREE(inargs);
#else
			safe_free(inargs);
#endif

		if (silent)
			return 0;

		if (!tres) {
			data->args_totlen += strlen(data->args_buf+data->args_totlen);
			return tres;
		}

	}

	lt_args_cb_arg(cfg, arg, pval, data, 1, 0, tsd);

	if ((cfg->args_detailed) &&
	    (LT_ARGS_DTYPE_STRUCT == arg->dtype))
		process_detailed_struct(cfg, arg, pval, data, regs, 0, tsd);

	return 0;
}
