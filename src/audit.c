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


#include <link.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <bits/wordsize.h>
#include <gnu/lib-names.h>
#include <stdlib.h>

#include "config.h"
#include "elfh.h"


extern struct lt_config_audit cfg;

static __thread int pipe_fd = 0;
static __thread int flow_below_stack = 0;
static __thread int indent_depth = 0;
static __thread char suppress_while[128];
static __thread int suppress_collapsed;
static __thread int suppress_nested = 0;
__thread char *fault_reason = NULL;
#ifdef TRANSFORMER_CRASH_PROTECTION
__thread jmp_buf crash_insurance;
__thread int jmp_set;
__thread int last_operation = -1;
__thread const char *last_symbol = NULL;
#endif


static int check_names(char *name, char **ptr)
{
	char *n;
	int matched = 0;

	for(n = *ptr; n; n = *(++ptr)) {
		size_t nlen;
		unsigned char last_char;

		if (!strcmp(name, n)) {
			matched = 1;
			break;
		}

		nlen = strlen(n);
		last_char = n[nlen-1];

		if (n[0] == '*' && last_char != '*' &&
		    strcmp(&(n[1]), name) == 0) {
			matched = 1;
		}
		else if (last_char == '*') {
			if ((n[0] != '*') && (strncmp(name, n, nlen-1) == 0))
				matched = 1;
			else if ((n[0] == '*') && (memmem(name, strlen(name), &(n[1]), nlen-2)))
				matched = 1;
			
		}

		if (matched)
			break;
	}

	if (matched) {
		PRINT_VERBOSE(&cfg, 2,
			"return %d for name %s\n", 1, name);
		return 1;
	}

	PRINT_VERBOSE(&cfg, 2, "return %d for name %s\n",
			0, name);
	return 0;
}

static int check_flow_below(const char *symname, int in)
{
	int ret = flow_below_stack;

	if (check_names((char*) symname, cfg.flow_below))
		in ? ret = ++flow_below_stack : flow_below_stack--;

	return ret;
}

static void free_argbuf(int argret, char *argbuf, char *argdbuf)
{
	if (argret)
		return;

	free(argbuf);
	if (lt_sh(&cfg, args_detailed) && (*argdbuf))
		free(argdbuf);
}

static int sym_entry(const char *symname, void *ptr,
		     char *lib_from, char *lib_to, La_regs *regs)
{
	int argret = -1;
	char *argbuf = "", *argdbuf = "";
	struct timeval tv;
	struct lt_symbol *sym = NULL;
	int collapsed = 0, set_suppress_collapsed = 0, is_silent = 0;

	PRINT_VERBOSE(&cfg, 2, "%s@%s\n", symname, lib_to);

	// Make sure we keep track of recursive/repeated calls to ourselves.
/*	if (suppress_while[0] && (suppress_collapsed != COLLAPSED_TERSE)) {
		if (!strcmp(suppress_while, symname))
			suppress_nested++;

		is_silent = 1;
	} */
	if (suppress_while[0] && (!strcmp(suppress_while, symname)))
		suppress_nested++;
//	if (suppress_while[0] && (suppress_collapsed != COLLAPSED_TERSE))
	if (suppress_while[0])
		is_silent = 1;

	if (is_silent) {
		if (lt_sh(&cfg, global_symbols))
			sym = lt_symbol_get(cfg.sh, ptr, symname);

		if (sym && sym->args->args[LT_ARGS_RET]->latrace_custom_func_intercept) {
		#ifdef CONFIG_ARCH_HAVE_ARGS
			argret = lt_args_sym_entry(cfg.sh, sym, regs, &argbuf, &argdbuf, is_silent);
			free_argbuf(argret, argbuf, argdbuf);
		#endif
		}

		return -1;
	}

	if (suppress_collapsed == COLLAPSED_TERSE) {
		collapsed = COLLAPSED_NESTED;
	}
	else {
//	else if (collapsed != COLLAPSED_NESTED) {

		if (cfg.flow_below_cnt && !check_flow_below(symname, 1))
			return -1;

		if (lt_sh(&cfg, timestamp) || lt_sh(&cfg, counts))
			gettimeofday(&tv, NULL);

		if (lt_sh(&cfg, global_symbols))
			sym = lt_symbol_get(cfg.sh, ptr, symname);

		if (sym && sym->collapsed) {
			strncpy(suppress_while, sym->name, sizeof(suppress_while)-1);
			suppress_while[sizeof(suppress_while)-1] = 0;
			suppress_nested++;
			collapsed = sym->collapsed;
			set_suppress_collapsed = 1;
		}

	#ifdef CONFIG_ARCH_HAVE_ARGS
		argret = lt_sh(&cfg, args_enabled) ?
			lt_args_sym_entry(cfg.sh, sym, regs, &argbuf, &argdbuf, is_silent) : -1;
	#endif
	}

	if (lt_sh(&cfg, pipe)) {
		char buf[FIFO_MSG_MAXLEN];
		int len;

		if (!pipe_fd)
			pipe_fd = lt_fifo_create(&cfg, cfg.dir);

		if (pipe_fd == -1)
			return -1;

		len = lt_fifo_msym_get(&cfg, buf, FIFO_MSG_TYPE_ENTRY, &tv,
				(char*) symname, lib_to, argbuf, argdbuf, collapsed);

		free_argbuf(argret, argbuf, argdbuf);

		if (set_suppress_collapsed)
			suppress_collapsed = collapsed;

		return lt_fifo_send(&cfg, pipe_fd, buf, len);
	}

	if (collapsed != COLLAPSED_NESTED)
		indent_depth++;

	if (set_suppress_collapsed)
		suppress_collapsed = collapsed;

	lt_out_entry(cfg.sh, &tv, syscall(SYS_gettid),
			indent_depth, collapsed,
			symname, lib_to,
			argbuf, argdbuf);

	free_argbuf(argret, argbuf, argdbuf);

	return 0;
}

static int sym_exit(const char *symname, void *ptr,
			 char *lib_from, char *lib_to,
			 const La_regs *inregs, La_retval *outregs)
{
	int argret = -1;
	char *argbuf = "", *argdbuf = "";
	struct timeval tv;
	struct lt_symbol *sym = NULL;
	int collapsed = 0, is_silent = 0;

	PRINT_VERBOSE(&cfg, 2, "%s@%s\n", symname, lib_to);

	if (suppress_while[0]) {
		if (!strcmp(suppress_while, symname)) {
			suppress_nested--;

			if (!suppress_nested) {
				memset(suppress_while, 0, sizeof(suppress_while));
				suppress_collapsed = 0;
			} else
				is_silent = 1;

		}
		else if (suppress_nested > 0)
			is_silent = 1;
	}

	if (is_silent) {
		if (lt_sh(&cfg, global_symbols))
			sym = lt_symbol_get(cfg.sh, ptr, symname);

		if (sym && sym->args->args[LT_ARGS_RET]->latrace_custom_func_intercept) {
		#ifdef CONFIG_ARCH_HAVE_ARGS
			argret = lt_args_sym_exit(cfg.sh, sym, (La_regs*) inregs, outregs, &argbuf, &argdbuf, is_silent);
			free_argbuf(argret, argbuf, argdbuf);
		#endif
		}

		return 0;
	}

	if (cfg.flow_below_cnt && !check_flow_below(symname, 0))
		return 0;

	if (lt_sh(&cfg, timestamp) || lt_sh(&cfg, counts))
		gettimeofday(&tv, NULL);

	if (lt_sh(&cfg, global_symbols))
		sym = lt_symbol_get(cfg.sh, ptr, symname);

	if (sym && sym->collapsed)
		collapsed = sym->collapsed;

#ifdef CONFIG_ARCH_HAVE_ARGS
	argret = lt_sh(&cfg, args_enabled) ?
		lt_args_sym_exit(cfg.sh, sym,
			(La_regs*) inregs, outregs, &argbuf, &argdbuf, is_silent) : -1;
#endif

	if (lt_sh(&cfg, pipe)) {
		char buf[FIFO_MSG_MAXLEN];
		int len;
		int collapsed = 0;

		if (sym && sym->collapsed)
			collapsed = sym->collapsed;

		len = lt_fifo_msym_get(&cfg, buf, FIFO_MSG_TYPE_EXIT, &tv,
				(char*) symname, lib_to, argbuf, argdbuf, collapsed);

		free_argbuf(argret, argbuf, argdbuf);

		return lt_fifo_send(&cfg, pipe_fd, buf, len);
	}

	lt_out_exit(cfg.sh, &tv, syscall(SYS_gettid),
			indent_depth, collapsed,
			symname, lib_from,
			argbuf, argdbuf);

	if (indent_depth)
		indent_depth--;

	free_argbuf(argret, argbuf, argdbuf);

	return 0;
}

static int check_pid()
{
	pid_t pid = getpid();

	PRINT_VERBOSE(&cfg, 1, "tid = %d, cfg tid = %d\n",
			pid, lt_sh(&cfg, pid));

	if (pid != lt_sh(&cfg, pid))
		return -1;

	return 0;
}

#define CHECK_PID(ret) \
do { \
	if (cfg.sh->not_follow_fork && \
	    check_pid()) \
		return ret; \
} while(0)

#define CHECK_DISABLED(ret) \
do { \
	if (lt_sh(&cfg, disabled)) \
		return ret; \
} while(0)

#ifdef TRANSFORMER_CRASH_PROTECTION
	#define LA_ENTER(x)	jmp_set = x;
	#define LA_RET(x)	{ jmp_set = 0; return x; }
#else
	#define LA_ENTER(x)	;
	#define LA_RET(x)	return x;
#endif

unsigned int la_version(unsigned int v)
{
	LA_ENTER(CODE_LOC_LA_VERSION);
	LA_RET(v)
}

unsigned int la_objopen(struct link_map *l, Lmid_t a, uintptr_t *cookie)
{
	symbol_mapping_t *pmap = NULL;
	char *name = l->l_name;
	size_t msize = 0;
	int res;

	LA_ENTER(CODE_LOC_LA_OBJOPEN);

	if (!cfg.init_ok)
		LA_RET(0);

	if (!name)
		LA_RET(0);

	if ((res = get_all_symbols(l, &pmap, &msize, 0)) > 0)
		store_link_map_symbols(l, pmap, msize);

	/* executable itself */
	if (!(*name))
		LA_RET(LA_FLG_BINDTO | LA_FLG_BINDFROM);

	/* audit all as default */
	if ((!cfg.libs_to_cnt) &&
	    (!cfg.libs_from_cnt) &&
	    (!cfg.libs_both_cnt))
		LA_RET(LA_FLG_BINDTO | LA_FLG_BINDFROM);

	if (check_names(name, cfg.libs_to))
		LA_RET(LA_FLG_BINDTO);

	if (check_names(name, cfg.libs_from))
		LA_RET(LA_FLG_BINDFROM);

	if (check_names(name, cfg.libs_both))
		LA_RET(LA_FLG_BINDTO | LA_FLG_BINDFROM);

	/* wrong library name specified ? */
	LA_RET(0);
}

static unsigned int la_symbind(ElfW(Sym) *sym, const char *symname)
{
	unsigned int flags = 0;

	LA_ENTER(CODE_LOC_LA_SYMBIND);

	/* particular symbols specified, omit all others */
	if (cfg.symbols_cnt) {
		flags = LA_SYMB_NOPLTENTER|LA_SYMB_NOPLTEXIT;
		if (check_names((char*) symname, cfg.symbols))
			flags = 0;
	}

	/* we might want just pltenter for some.. eg for _setjmp */
	if (cfg.symbols_noexit_cnt) {
		if (check_names((char*) symname, cfg.symbols_noexit))
			flags = LA_SYMB_NOPLTEXIT;
	}

	/* and keep omit options the strongest */
	if (cfg.symbols_omit_cnt) {
		if (check_names((char*) symname, cfg.symbols_omit))
			flags = LA_SYMB_NOPLTENTER|LA_SYMB_NOPLTEXIT;
	}

	/* we are interested in this symbol */
	if (lt_sh(&cfg, global_symbols) &&
	    !(flags & LA_SYMB_NOPLTENTER))
		lt_symbol_bind(cfg.sh, (void*) sym->st_value, symname);

	LA_RET(flags);
}

void la_activity(uintptr_t *cookie, unsigned int act)
{
	LA_ENTER(CODE_LOC_LA_ACTIVITY);
	PRINT_VERBOSE(&cfg, 2, "%s\n", "entry");
	LA_RET();
}

char* la_objsearch(const char *name, uintptr_t *cookie, unsigned int flag)
{
	LA_ENTER(CODE_LOC_LA_OBJSEARCH);

	if (flag == LA_SER_ORIG)
		LA_RET((char*) name);

	LA_RET(lt_objsearch(&cfg, name, cookie, flag));
}

void la_preinit(uintptr_t *__cookie)
{
	LA_ENTER(CODE_LOC_LA_PREINIT);
	PRINT_VERBOSE(&cfg, 2, "%s\n", "entry");
	LA_RET();
}

unsigned int la_objclose(uintptr_t *__cookie)
{
	LA_ENTER(CODE_LOC_LA_OBJCLOSE);
	PRINT_VERBOSE(&cfg, 2, "%s\n", "entry");
	LA_RET(0);
}

#if __ELF_NATIVE_CLASS == 32
uintptr_t la_symbind32(Elf32_Sym *sym, unsigned int ndx, uintptr_t *refcook,
		uintptr_t *defcook, unsigned int *flags, const char *symname)
{
	LA_ENTER(CODE_LOC_LA_SYMBIND_NATIVE);
	*flags = la_symbind(sym, symname);
	LA_RET(sym->st_value);
}
#elif __ELF_NATIVE_CLASS == 64
uintptr_t la_symbind64(Elf64_Sym *sym, unsigned int ndx, uintptr_t *refcook,
		uintptr_t *defcook, unsigned int *flags, const char *symname)
{
	LA_ENTER(CODE_LOC_LA_SYMBIND_NATIVE);
	*flags = la_symbind(sym, symname);
	LA_RET(sym->st_value);
}
#endif

ElfW(Addr)
pltenter(ElfW(Sym) *sym, unsigned int ndx, uintptr_t *refcook,
          uintptr_t *defcook, La_regs *regs, unsigned int *flags,
          const char *symname, long int *framesizep)
{
	struct link_map *lr = (struct link_map*) *refcook;
	struct link_map *ld = (struct link_map*) *defcook;
	int ret = 0;

	LA_ENTER(CODE_LOC_LA_PLTENTER);
#ifdef TRANSFORMER_CRASH_PROTECTION
	last_symbol = symname;
	last_operation = 0;
#endif

	do {
		CHECK_DISABLED(sym->st_value);

		CHECK_PID(sym->st_value);

		ret = sym_entry(symname, (void*) sym->st_value,
			  lr ? lr->l_name : NULL,
			  ld ? ld->l_name : NULL,
			  regs);

	} while(0);

	if (ret < 0)
		LA_RET(sym->st_value);

	*framesizep = lt_stack_framesize(&cfg, regs);

	LA_RET(sym->st_value);
}

unsigned int pltexit(ElfW(Sym) *sym, unsigned int ndx, uintptr_t *refcook,
         uintptr_t *defcook, const La_regs *inregs, La_retval *outregs,
         const char *symname)
{
	struct link_map *lr = (struct link_map*) *refcook;
	struct link_map *ld = (struct link_map*) *defcook;

	LA_ENTER(CODE_LOC_LA_PLTEXIT);
#ifdef TRANSFORMER_CRASH_PROTECTION
	last_symbol = symname;
	last_operation = 1;
#endif

	do {
		CHECK_PID(0);

		sym_exit(symname, (void*) sym->st_value,
			 lr ? lr->l_name : NULL,
			 ld ? ld->l_name : NULL,
			 inregs, outregs);

	} while(0);

	LA_RET(0);
}

#ifdef TRANSFORMER_CRASH_PROTECTION
void
inline crash_handler_internal(void)
{
	if (jmp_set) {
		switch (jmp_set) {
			case CODE_LOC_LA_TRANSFORMER:
				fault_reason = "internal transformer violation";
				break;
			case CODE_LOC_LA_INTERCEPT:
				fault_reason = "internal intercept violation";
				break;
			case CODE_LOC_LA_VERSION:
				fault_reason = "audit version hook";
				break;
			case CODE_LOC_LA_OBJOPEN:
				fault_reason = "audit object open hook";
				break;
			case CODE_LOC_LA_SYMBIND:
				fault_reason = "audit symbol bind hook";
				break;
			case CODE_LOC_LA_ACTIVITY:
				fault_reason = "audit activity hook";
				break;
			case CODE_LOC_LA_OBJSEARCH:
				fault_reason = "audit object search hook";
				break;
			case CODE_LOC_LA_PREINIT:
				fault_reason = "audit pre initialization hook";
				break;
			case CODE_LOC_LA_OBJCLOSE:
				fault_reason = "audit object close hook";
				break;
			case CODE_LOC_LA_SYMBIND_NATIVE:
				fault_reason = "audit symbolbind arch hook";
				break;
			case CODE_LOC_LA_PLTENTER:
				fault_reason = "audit PLT entry hook";
				break;
			case CODE_LOC_LA_PLTEXIT:
				fault_reason = "audit PLT exit hook";
				break;
			default:
				fault_reason = "unknown INTERNAL error";
				break;
		}
		
		if (jmp_set == CODE_LOC_LA_TRANSFORMER || jmp_set == CODE_LOC_LA_INTERCEPT)
			longjmp(crash_insurance, 666);

		PRINT_ERROR("Warning: signal appeared to be generated by internal latrace routine (%s).\n",
			fault_reason);

		if (last_operation >= 0)
			PRINT_ERROR("Last known operation before crash: %s / %s\n", last_symbol,
				(!last_operation ? "entry" : "exit"));

		PRINT_ERROR("%s", "Exiting immediately.\n");
		_exit(-1);
	} else {
		fault_reason = "unknown error";
		PRINT_ERROR("%s", "Warning: signal appeared to be delivered outside of user custom code.\n");

		if (last_operation >= 0)
			PRINT_ERROR("Last known operation before crash: %s / %s\n", last_symbol,
				(!last_operation ? "entry" : "exit"));

		PRINT_ERROR("%s", "Exiting immediately.\n");
		_exit(-1);
	}

	return;
}

#ifndef TRANSFORMER_CRASH_PROTECTION_ENHANCED
static void crash_handler(int signo)
{
	PRINT_ERROR("Warning: caught potentially fatal signal: %d\n", signo);
	crash_handler_internal();
}
#else
static void
crash_handler_si(int signo, siginfo_t *si, void *ucontext)
{
	const char *more_info = "additional information unavailable";

	if (signo == SIGSEGV) {
		if (si->si_code == SEGV_MAPERR)
			more_info = "address not mapped to object";
		else if (si->si_code == SEGV_ACCERR)
			more_info = "invalid permissions for mapped object";
		else
			more_info = "unknown SIGSEGV violation subtype";
	}

	PRINT_ERROR("Warning: caught potentially fatal signal: %d (code = %d (%s), addr = %p)\n",
		signo, si->si_code, more_info, si->si_addr);
	crash_handler_internal();
}
#endif
#endif

int setup_crash_handlers(void)
{
#ifdef TRANSFORMER_CRASH_PROTECTION
	struct sigaction sa;

	printf("Setting up crash handler...\n");

	memset(&sa, 0, sizeof(struct sigaction));
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;

#ifdef TRANSFORMER_CRASH_PROTECTION_ENHANCED
	sa.sa_sigaction = crash_handler_si;
	sa.sa_flags |= SA_SIGINFO;
#else
	sa.sa_handler = crash_handler;
#endif

	if ((sigaction(SIGILL, &sa, NULL) == -1) || (sigaction(SIGBUS, &sa, NULL) == -1) ||
		(sigaction(SIGSEGV, &sa, NULL) == -1)) {
		perror("sigaction");
		return -1;
	}

#endif
	return 0;
}
