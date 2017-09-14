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
#include <errno.h>
#include <pthread.h>

#include "config.h"
#include "elfh.h"


extern struct lt_config_audit cfg;

unsigned int thread_warning = 0;

#define MAXPTIDS	256
#define MAXIDX		3

#define PKEY_VAL_INITIALIZED	(void *)0xc0ffee
#define PKEY_VAL_TLS_BAD	(void *)0xdeadbeef

#define PKEY_ID_THREAD_STATE	0
#define PKEY_ID_TSD		1
#define PKEY_ID_EXCISED		2
#define PKEY_ID_MARK_TLS	3

int lt_thread_pkey_init = 0;
static pthread_key_t lt_thread_pkey, lt_tsd_pkey;
pid_t master_thread = 0;

#ifdef USE_GLIBC_FEATURES
static __thread lt_tsd_t *this_tsd = NULL;
#endif

static pthread_mutex_t tsd_lock = PTHREAD_MUTEX_INITIALIZER;

lt_tsd_t *thread_get_tsd(int create);


STATIC int check_names(char *name, char **ptr)
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

STATIC int check_flow_below(const char *symname, int in, lt_tsd_t *tsd)
{
	int ret = tsd->flow_below_stack;

	if (check_names((char*) symname, cfg.flow_below))
		in ? ret = ++tsd->flow_below_stack : tsd->flow_below_stack--;

	return ret;
}

STATIC void free_argbuf(int argret, char *argbuf, char *argdbuf)
{
#ifdef USE_GLIBC_FEATURES
	XFREE(argbuf);
#else
//	safe_free(argbuf);
#endif

	if (argret)
		return;

	if (lt_sh(&cfg, args_detailed) && (*argdbuf))
		XFREE(argdbuf);
}

STATIC int sym_entry(const char *symname, void *ptr,
		     char *lib_from, char *lib_to, La_regs *regs, lt_tsd_t *tsd)
{
	int argret = -1;
	char *argbuf, *argdbuf = "";
	struct timeval tv;
	struct lt_symbol *sym = NULL;
	int collapsed = 0, set_suppress_collapsed = 0, is_silent = 0;

#ifdef USE_GLIBC_FEATURES
	XMALLOC_ASSIGN(argbuf, LR_ARGS_MAXLEN);
#else
	argbuf = alloca(LR_ARGS_MAXLEN);
#endif
	memset(argbuf, 0, LR_ARGS_MAXLEN);

	PRINT_VERBOSE(&cfg, 2, "%s@%s\n", symname, lib_to);

	// Make sure we keep track of recursive/repeated calls to ourselves.
/*	if (tsd->suppress_while[0] && (tsd->suppress_collapsed != COLLAPSED_TERSE)) {
		if (!strcmp(tsd->suppress_while, symname))
			tsd->suppress_nested++;

		is_silent = 1;
	} */
	if (tsd->suppress_while[0] && (!strcmp(tsd->suppress_while, symname)))
		tsd->suppress_nested++;
//	if (tsd->suppress_while[0] && (tsd->suppress_collapsed != COLLAPSED_TERSE))
	if (tsd->suppress_while[0])
		is_silent = 1;

	if (is_silent) {
		if (lt_sh(&cfg, global_symbols))
			sym = lt_symbol_get(cfg.sh, ptr, symname);

		if (sym && sym->args->args[LT_ARGS_RET]->latrace_custom_func_intercept) {
		#ifdef CONFIG_ARCH_HAVE_ARGS
			argret = lt_args_sym_entry(cfg.sh, sym, regs, argbuf, LR_ARGS_MAXLEN, &argdbuf, is_silent, tsd);
		#endif
		}

		if ((tsd->suppress_collapsed != COLLAPSED_NESTED) && (tsd->suppress_collapsed != COLLAPSED_TERSE))
			symname = "";

		collapsed = COLLAPSED_NESTED;
	}

	if (!is_silent && (tsd->suppress_collapsed == COLLAPSED_TERSE)) {
		collapsed = COLLAPSED_NESTED;
	}
	else if (!is_silent) {
//	else if (collapsed != COLLAPSED_NESTED) {

		if (cfg.flow_below_cnt && !check_flow_below(symname, 1, tsd))
			return -1;

		if (lt_sh(&cfg, timestamp) || lt_sh(&cfg, counts))
			gettimeofday(&tv, NULL);

		if (lt_sh(&cfg, global_symbols))
			sym = lt_symbol_get(cfg.sh, ptr, symname);

		if (sym && sym->collapsed) {
			strncpy(tsd->suppress_while, sym->name, sizeof(tsd->suppress_while)-1);
			tsd->suppress_while[sizeof(tsd->suppress_while)-1] = 0;
			tsd->suppress_nested++;
			collapsed = sym->collapsed;
			set_suppress_collapsed = 1;
		}

	#ifdef CONFIG_ARCH_HAVE_ARGS
		argret = lt_sh(&cfg, args_enabled) ?
			lt_args_sym_entry(cfg.sh, sym, regs, argbuf, LR_ARGS_MAXLEN, &argdbuf, is_silent, tsd) : -1;
	#endif
	}

	if (lt_sh(&cfg, pipe)) {
		char buf[FIFO_MSG_MAXLEN];
		int len;

		if (!tsd->pipe_fd)
			tsd->pipe_fd = lt_fifo_create(&cfg, cfg.dir);

		if (tsd->pipe_fd == -1)
			return -1;

		if (tsd->excised) {
			len = lt_fifo_msym_get(&cfg, buf, FIFO_MSG_TYPE_ENTRY, &tv,
					"", lib_to, tsd->excised, argdbuf, collapsed);
			lt_fifo_send(&cfg, tsd->pipe_fd, buf, len);
			safe_free(tsd->excised);
			tsd->excised = NULL;
		}

		len = lt_fifo_msym_get(&cfg, buf, FIFO_MSG_TYPE_ENTRY, &tv,
				(char*) symname, lib_to, argbuf, argdbuf, collapsed);

		free_argbuf(argret, argbuf, argdbuf);

		if (!is_silent && set_suppress_collapsed)
			tsd->suppress_collapsed = collapsed;

		return lt_fifo_send(&cfg, tsd->pipe_fd, buf, len);
	}

	tsd->indent_depth++;

	if (!is_silent && set_suppress_collapsed)
		tsd->suppress_collapsed = collapsed;

	if (tsd->excised) {
		lt_out_entry(cfg.sh, &tv, syscall(SYS_gettid), tsd->indent_depth, collapsed,
			"", lib_to, tsd->excised, argdbuf, &tsd->nsuppressed);
		safe_free(tsd->excised);
		tsd->excised = NULL;
	}

	/* If symname is empty then all we care about is preserving the call stack depth */
	if (*symname) {
		lt_out_entry(cfg.sh, &tv, syscall(SYS_gettid), tsd->indent_depth, collapsed,
			symname, lib_to, argbuf, argdbuf, &tsd->nsuppressed);
	}

	free_argbuf(argret, argbuf, argdbuf);
	return 0;
}

STATIC int sym_exit(const char *symname, void *ptr, char *lib_from, char *lib_to,
			 const La_regs *inregs, La_retval *outregs, lt_tsd_t *tsd)
{
	int argret = -1;
	char *argbuf, *argdbuf = "";
	struct timeval tv;
	struct lt_symbol *sym = NULL;
	int collapsed = 0, is_silent = 0;

#ifdef USE_GLIBC_FEATURES
	XMALLOC_ASSIGN(argbuf, LR_ARGS_MAXLEN);
#else
	argbuf = alloca(LR_ARGS_MAXLEN);
#endif
	memset(argbuf, 0, LR_ARGS_MAXLEN);

	PRINT_VERBOSE(&cfg, 2, "%s@%s\n", symname, lib_to);

	if (tsd->suppress_while[0]) {
		if (!strcmp(tsd->suppress_while, symname)) {
			tsd->suppress_nested--;

			if (!tsd->suppress_nested) {
				memset(tsd->suppress_while, 0, sizeof(tsd->suppress_while));
				tsd->suppress_collapsed = 0;
			} else
				is_silent = 1;

		}
		else if (tsd->suppress_nested > 0)
			is_silent = 1;
	}

	if (is_silent) {
		if (lt_sh(&cfg, global_symbols))
			sym = lt_symbol_get(cfg.sh, ptr, symname);

		if (sym && sym->args->args[LT_ARGS_RET]->latrace_custom_func_intercept) {
		#ifdef CONFIG_ARCH_HAVE_ARGS
			argret = lt_args_sym_exit(cfg.sh, sym, (La_regs*) inregs, outregs, argbuf, LR_ARGS_MAXLEN, &argdbuf, is_silent, tsd);
		#endif
		}

		collapsed = COLLAPSED_NESTED;
	} else {

		if (cfg.flow_below_cnt && !check_flow_below(symname, 0, tsd))
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
				(La_regs*) inregs, outregs, argbuf, LR_ARGS_MAXLEN, &argdbuf, is_silent, tsd) : -1;
#endif
	}

	if (lt_sh(&cfg, pipe)) {
		char buf[FIFO_MSG_MAXLEN];
		int len;

		if (!is_silent && sym && sym->collapsed)
			collapsed = sym->collapsed;

		len = lt_fifo_msym_get(&cfg, buf, FIFO_MSG_TYPE_EXIT, &tv,
				(char*) symname, lib_to, argbuf, argdbuf, collapsed);

		free_argbuf(argret, argbuf, argdbuf);

		return lt_fifo_send(&cfg, tsd->pipe_fd, buf, len);
	}

	lt_out_exit(cfg.sh, &tv, syscall(SYS_gettid),
			tsd->indent_depth, collapsed,
			symname, lib_from,
			argbuf, argdbuf, &tsd->nsuppressed);

	if (tsd->indent_depth)
		tsd->indent_depth--;

	free_argbuf(argret, argbuf, argdbuf);
	return 0;
}

STATIC int check_pid()
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
	#define LA_ENTER(x)	TSD_SET(jmp_set,x)
	#define LA_RET(x)	{ TSD_SET(jmp_set,0); return x; }
#else
	#define LA_ENTER(x)	;
	#define LA_RET(x)	return x;
#endif

unsigned int la_version(unsigned int v)
{
	lt_tsd_t *tsd = NULL;

	if (!(tsd = thread_get_tsd(1))) {
		PRINT_ERROR("Could not get TSD for la_version() in thread %ld\n", syscall(SYS_gettid));
		return v;
	}

	LA_ENTER(CODE_LOC_LA_VERSION);
	LA_RET(v)
}

unsigned int la_objopen(struct link_map *l, Lmid_t a, uintptr_t *cookie)
{
	lt_tsd_t *tsd = NULL;
	symbol_mapping_t *pmap = NULL;
	char *name = l->l_name;
	size_t msize = 0;
	int res;

	if (!(tsd = thread_get_tsd(1))) {
		PRINT_ERROR("Could not get TSD for la_objopen() in thread %ld\n", syscall(SYS_gettid));
		return 0;
	}

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

STATIC unsigned int la_symbind(ElfW(Sym) *sym, const char *symname, lt_tsd_t *tsd)
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
	if (tsd && lt_sh(&cfg, global_symbols) &&
	    !(flags & LA_SYMB_NOPLTENTER))
		lt_symbol_bind(cfg.sh, (void*) sym->st_value, symname);

	LA_RET(flags);
}

void la_activity(uintptr_t *cookie, unsigned int act)
{
	lt_tsd_t *tsd = NULL;

	if (!(tsd = thread_get_tsd(1))) {
		PRINT_ERROR("Could not get TSD for la_activity() in thread %ld\n", syscall(SYS_gettid));
		return;
	}

	LA_ENTER(CODE_LOC_LA_ACTIVITY);
	PRINT_VERBOSE(&cfg, 2, "%s\n", "entry");
	LA_RET();
}

char* la_objsearch(const char *name, uintptr_t *cookie, unsigned int flag)
{
	lt_tsd_t *tsd = NULL;

	if (!(tsd = thread_get_tsd(1))) {
		PRINT_ERROR("Could not get TSD for la_objsearch() in thread %ld\n", syscall(SYS_gettid));
		return (char *)name;
	}

	LA_ENTER(CODE_LOC_LA_OBJSEARCH);

	if (flag == LA_SER_ORIG)
		LA_RET((char*) name);

	LA_RET(lt_objsearch(&cfg, name, cookie, flag));
}

void la_preinit(uintptr_t *__cookie)
{
	lt_tsd_t *tsd = NULL;

	glibc_unsafe = 1;

	if (!(tsd = thread_get_tsd(1))) {
		PRINT_ERROR("Could not get TSD for la_preinit() in thread %ld\n", syscall(SYS_gettid));
		return;
	}

	LA_ENTER(CODE_LOC_LA_PREINIT);
	PRINT_VERBOSE(&cfg, 2, "%s\n", "entry");
	LA_RET();
}

unsigned int la_objclose(uintptr_t *__cookie)
{
	lt_tsd_t *tsd = NULL;

	if (!(tsd = thread_get_tsd(1))) {
		PRINT_ERROR("Could not get TSD for la_objclose() in thread %ld\n", syscall(SYS_gettid));
		return 0;
	}

	LA_ENTER(CODE_LOC_LA_OBJCLOSE);
	PRINT_VERBOSE(&cfg, 2, "%s\n", "entry");
	LA_RET(0);
}


#if __ELF_NATIVE_CLASS == 32
uintptr_t la_symbind32(Elf32_Sym *sym, unsigned int ndx, uintptr_t *refcook,
		uintptr_t *defcook, unsigned int *flags, const char *symname)
{
	lt_tsd_t *tsd = NULL;

	if (!(tsd = thread_get_tsd(1))) {
		PRINT_ERROR("Could not get TSD for la_symbind32() in thread %ld\n", syscall(SYS_gettid));
		*flags = la_symbind(sym, symname, tsd);
		return sym->st_value;
	}

	LA_ENTER(CODE_LOC_LA_SYMBIND_NATIVE);
	*flags = la_symbind(sym, symname, tsd);
	LA_RET(sym->st_value);
}
#elif __ELF_NATIVE_CLASS == 64
uintptr_t la_symbind64(Elf64_Sym *sym, unsigned int ndx, uintptr_t *refcook,
		uintptr_t *defcook, unsigned int *flags, const char *symname)
{
	lt_tsd_t *tsd = NULL;

	if (!(tsd = thread_get_tsd(1))) {
		PRINT_ERROR("Could not get TSD for la_symbind64() / %s in thread %ld\n", symname, syscall(SYS_gettid));
		*flags = la_symbind(sym, symname, tsd);
		return sym->st_value;
	}

	LA_ENTER(CODE_LOC_LA_SYMBIND_NATIVE);
	*flags = la_symbind(sym, symname, tsd);
	LA_RET(sym->st_value);
}
#endif

/*
 * Tried consoldating this into one single array where:
 * thread_data[MAXPTIDS] and void *data[MAXIDX]
 * but this didn't work for some unknown reason. Should revisit.
 */
typedef struct lt_thread_pkey {
	pid_t tid;
	void *data;
} lt_thread_pkey_t;

static lt_thread_pkey_t thread_data[MAXIDX][MAXPTIDS];

STATIC int
SETSPECIFIC(pid_t tid, size_t idx, void *data, int *found) {
	size_t t;

	if (idx >= MAXIDX)
		return -1;

	pthread_mutex_lock(&tsd_lock);

	for (t = 0; t < MAXPTIDS; t++) {

		if ((thread_data[idx][t].tid == 0) || (thread_data[idx][t].tid == tid)) {
			thread_data[idx][t].tid = tid;
			thread_data[idx][t].data = data;
			pthread_mutex_unlock(&tsd_lock);
			return 0;
		}

	}

	pthread_mutex_unlock(&tsd_lock);
	return -1;
//	return pthread_setspecific(lt_thread_pkey, data);
}

// XXX: probably doesn't require locking here
STATIC void *
GETSPECIFIC(pid_t tid, size_t idx, int *found) {
	void *result = NULL;
	size_t t;

	if (found)
		*found = 0;

	if (idx >= MAXIDX)
		return NULL;

	pthread_mutex_lock(&tsd_lock);

	for (t = 0; t < MAXPTIDS; t++) {

		if (thread_data[idx][t].tid == tid) {
			result = thread_data[idx][t].data;

			if (found)
				*found = 1;

			break;
		}

	}

	pthread_mutex_unlock(&tsd_lock);
	return result;
//	return pthread_getspecific(lt_thread_pkey);
}

STATIC
int thread_tls_mark(pid_t tid, int set)
{
	int res = 0;
	int found = 0;

	if (set > 0) {
		SETSPECIFIC(tid, PKEY_ID_MARK_TLS, (void *)1, &found);
		return found;
	} else if (set < 0) {
		SETSPECIFIC(tid, PKEY_ID_MARK_TLS, (void *)0, &found);
		return found;
	}

	res = (int)GETSPECIFIC(tid, PKEY_ID_MARK_TLS, &found);

	if (!found)
		return 0;

	return res;
}

void
setup_tsd_pkeys(void)
{

	if (lt_thread_pkey_init != 0)
		return;

	master_thread = syscall(SYS_gettid);

	pthread_key_create(&lt_thread_pkey, NULL);
	if (pthread_key_create(&lt_thread_pkey, NULL) != 0) {
		PRINT_ERROR("Failed to create thread specific data: %s\n", strerror(errno));
		lt_thread_pkey_init = -1;
	} else if (pthread_key_create(&lt_tsd_pkey, NULL) != 0) {
		PRINT_ERROR("Failed to create thread specific data[2]: %s\n", strerror(errno));
		lt_thread_pkey_init = -1;
	} else {
//		pthread_setspecific(lt_thread_pkey, PKEY_VAL_INITIALIZED);
#ifdef USE_GLIBC_FEATURES
//		pthread_setspecific(lt_thread_pkey, (void *)(unsigned long)master_thread);
#else
		SETSPECIFIC(master_thread, PKEY_ID_THREAD_STATE, (void *)(unsigned long)master_thread, NULL);
#endif
		thread_get_tsd(2);
		lt_thread_pkey_init = 1;
	}

	return;
}

lt_tsd_t *
thread_get_tsd(int create)
{
	void *pkd;
	int found;
	unsigned long this_thread;

	if (create == 1 && !lt_thread_pkey_init)
		setup_tsd_pkeys();

	if (lt_thread_pkey_init <= 0)
		return NULL;

#ifdef USE_GLIBC_FEATURES
//	pkd = pthread_getspecific(lt_thread_pkey);
	pkd = this_tsd;

	if (!pkd && create) {
		lt_tsd_t *tsd;

		XMALLOC_ASSIGN(tsd, sizeof(lt_tsd_t));
		memset(tsd, 0, sizeof(*tsd));
		tsd->last_operation = -1;
		this_tsd = pkd = tsd;
//		pthread_setspecific(lt_thread_pkey, pkd);
	}

	return pkd;
#endif

	this_thread = syscall(SYS_gettid);

	pkd = GETSPECIFIC(this_thread, PKEY_ID_THREAD_STATE, NULL);
	found = (pkd == PKEY_VAL_INITIALIZED || pkd == PKEY_VAL_TLS_BAD ||
		pkd == (void *)this_thread);

	if (found && (pkd != PKEY_VAL_INITIALIZED) && pkd != (void *)this_thread)
		return NULL;

	if (!found && thread_tls_mark(syscall(SYS_gettid), 0) > 0)
		return NULL;

	pkd = GETSPECIFIC(this_thread, PKEY_ID_TSD, NULL);

	if (!pkd && create) {
		lt_tsd_t *tsd;

		//XMALLOC_ASSIGN(tsd, sizeof(lt_tsd_t));
		tsd = safe_malloc(4096);
		memset(tsd, 0, sizeof(*tsd));
		tsd->last_operation = -1;
		pkd = tsd;
		SETSPECIFIC(this_thread, PKEY_ID_TSD, pkd, NULL);
	}

	return (lt_tsd_t *)pkd;
}

ElfW(Addr)
pltenter(ElfW(Sym) *sym, unsigned int ndx, uintptr_t *refcook,
          uintptr_t *defcook, La_regs *regs, unsigned int *flags,
          const char *symname, long int *framesizep)
{
	lt_tsd_t *tsd = NULL;
	struct link_map *lr = (struct link_map*) *refcook;
	struct link_map *ld = (struct link_map*) *defcook;
	char *excised = NULL;
	int ret = 0;
	int tls_volatile = 0;
	pid_t this_thread = syscall(SYS_gettid);

	if (lt_thread_pkey_init < 0)
		return sym->st_value;
	else if (!lt_thread_pkey_init)
		setup_tsd_pkeys();

	tsd = thread_get_tsd(0);

#ifdef USE_GLIBC_FEATURES
	if (!tsd) {
		PRINT_ERROR("Could not get TSD for pltenter() in thread %d\n", this_thread);
		return sym->st_value;
	}

	LA_ENTER(CODE_LOC_LA_PLTENTER);
#ifdef TRANSFORMER_CRASH_PROTECTION
	TSD_SET(last_symbol, symname);
	TSD_SET(last_operation, 0);
#endif

	do {
		CHECK_DISABLED(sym->st_value);

		CHECK_PID(sym->st_value);

		ret = sym_entry(symname, (void*) sym->st_value,
			  lr ? lr->l_name : NULL,
			  ld ? ld->l_name : NULL,
			  regs, tsd);

	} while(0);

	if (ret < 0)
		LA_RET(sym->st_value);

	*framesizep = lt_stack_framesize(&cfg, regs, tsd);
	LA_RET(sym->st_value);
#endif

	if (!strcmp(symname, "__clone"))
		__sync_add_and_fetch(&thread_warning, 1);
	else if (!strcmp(symname, "__call_tls_dtors")) {
		PRINT_ERROR("Program appears to be shutting down... skipping tracing of internal function %s() / TID %d\n", symname, this_thread);
		thread_tls_mark(this_thread, 1);
		return sym->st_value;
	}

	if (this_thread != master_thread) {
		void *pkd = NULL;
		int found = 0;

		pkd = GETSPECIFIC(this_thread, PKEY_ID_THREAD_STATE, NULL);
		found = (pkd == PKEY_VAL_INITIALIZED || pkd == PKEY_VAL_TLS_BAD ||
			pkd == (void *)(unsigned long)this_thread);

		if (!found && thread_tls_mark(this_thread, 0) > 0) {
			int remove;

			remove = (!lr || !(lr->l_name) || !(strstr(lr->l_name, "libpthread.so")));
			tls_volatile = 1;

			if (remove) {
				excised = GETSPECIFIC(this_thread, PKEY_ID_EXCISED, NULL);
				SETSPECIFIC(this_thread, PKEY_ID_EXCISED, NULL, NULL);
				SETSPECIFIC(this_thread, PKEY_ID_THREAD_STATE, (void *)(unsigned long)this_thread, NULL);
				thread_tls_mark(this_thread, -1);
				tsd = thread_get_tsd(1);
				tls_volatile = 0;
			}

		} else if (!found && (thread_warning > 0)) {
			__sync_add_and_fetch(&thread_warning, -1);
			thread_tls_mark(this_thread, 1);
			SETSPECIFIC(this_thread, PKEY_ID_EXCISED, NULL, NULL);
			tls_volatile = 1;
		} else if (!found) {
			SETSPECIFIC(this_thread, PKEY_ID_THREAD_STATE, PKEY_VAL_INITIALIZED, NULL);
			SETSPECIFIC(this_thread, PKEY_ID_THREAD_STATE, (void *)(unsigned long)this_thread, NULL);
			tsd = thread_get_tsd(1);
		} else if (found && (pkd == PKEY_VAL_TLS_BAD)) {
			tls_volatile = 1;
		}

	}

	if (!tsd || tls_volatile) {
		if (!tsd) {
			size_t eleft, elen;
			char *prefix = "";

			excised = GETSPECIFIC(this_thread, PKEY_ID_EXCISED, NULL);

			if (!excised) {
				excised = safe_malloc(4096);
				memset(excised, 0, 4096);
			}

			elen = strlen(excised);

			if (elen)
				prefix = "; ";

			eleft = 4096 - elen;
			snprintf(&excised[elen], eleft, "%s%s(): cannot track function with TLS in volatile state", prefix, symname);
			SETSPECIFIC(this_thread, PKEY_ID_EXCISED, excised, NULL);
		}

		return sym->st_value;
	}

	LA_ENTER(CODE_LOC_LA_PLTENTER);
#ifdef TRANSFORMER_CRASH_PROTECTION
	TSD_SET(last_symbol, symname);
	TSD_SET(last_operation, 0);
#endif

	if (excised)
		tsd->excised = excised;

	do {
		CHECK_DISABLED(sym->st_value);

		CHECK_PID(sym->st_value);

		ret = sym_entry(symname, (void*) sym->st_value,
			  lr ? lr->l_name : NULL,
			  ld ? ld->l_name : NULL,
			  regs, tsd);

	} while(0);

	if (ret < 0)
		LA_RET(sym->st_value);

	// XXX: Why does this fail otherwise??
//	*framesizep = lt_stack_framesize(&cfg, regs, tsd);
	*framesizep = 1000;
	LA_RET(sym->st_value);
}

unsigned int pltexit(ElfW(Sym) *sym, unsigned int ndx, uintptr_t *refcook,
         uintptr_t *defcook, const La_regs *inregs, La_retval *outregs,
         const char *symname)
{
	lt_tsd_t *tsd = NULL;
	struct link_map *lr = (struct link_map*) *refcook;
	struct link_map *ld = (struct link_map*) *defcook;

	if (!(tsd = thread_get_tsd(0))) {
		PRINT_ERROR("Could not get TSD for pltexit() in thread %ld\n", syscall(SYS_gettid));
		return 0;
	}

	LA_ENTER(CODE_LOC_LA_PLTEXIT);
#ifdef TRANSFORMER_CRASH_PROTECTION
	TSD_SET(last_symbol, symname);
	TSD_SET(last_operation, 1);
#endif

	do {
		CHECK_PID(0);

		sym_exit(symname, (void*) sym->st_value,
			 lr ? lr->l_name : NULL,
			 ld ? ld->l_name : NULL,
			 inregs, outregs, tsd);

	} while(0);

	LA_RET(0);
}

#ifdef TRANSFORMER_CRASH_PROTECTION
void
inline crash_handler_internal(int *do_exit)
{
	lt_tsd_t *tsd = NULL;

	if (do_exit)
		*do_exit = 0;

	tsd = thread_get_tsd(0);

	if (TSD_GET(jmp_set,0)) {
		switch (TSD_GET(jmp_set,0)) {
			case CODE_LOC_LA_TRANSFORMER:
				TSD_SET(fault_reason, "internal transformer violation");
				break;
			case CODE_LOC_LA_INTERCEPT:
				TSD_SET(fault_reason, "internal intercept violation");
				break;
			case CODE_LOC_LA_VERSION:
				TSD_SET(fault_reason, "audit version hook");
				break;
			case CODE_LOC_LA_OBJOPEN:
				TSD_SET(fault_reason, "audit object open hook");
				break;
			case CODE_LOC_LA_SYMBIND:
				TSD_SET(fault_reason, "audit symbol bind hook");
				break;
			case CODE_LOC_LA_ACTIVITY:
				TSD_SET(fault_reason, "audit activity hook");
				break;
			case CODE_LOC_LA_OBJSEARCH:
				TSD_SET(fault_reason, "audit object search hook");
				break;
			case CODE_LOC_LA_PREINIT:
				TSD_SET(fault_reason, "audit pre initialization hook");
				break;
			case CODE_LOC_LA_OBJCLOSE:
				TSD_SET(fault_reason, "audit object close hook");
				break;
			case CODE_LOC_LA_SYMBIND_NATIVE:
				TSD_SET(fault_reason, "audit symbolbind arch hook");
				break;
			case CODE_LOC_LA_PLTENTER:
				TSD_SET(fault_reason, "audit PLT entry hook");
				break;
			case CODE_LOC_LA_PLTEXIT:
				TSD_SET(fault_reason, "audit PLT exit hook");
				break;
			default:
				TSD_SET(fault_reason, "unknown INTERNAL error");
				break;
		}
		
		if ((TSD_GET(jmp_set,0) == CODE_LOC_LA_TRANSFORMER) ||
			(TSD_GET(jmp_set,0) == CODE_LOC_LA_INTERCEPT))
			longjmp(TSD_GET(crash_insurance,NULL), 666);

		PRINT_ERROR("Warning: signal appeared to be generated by internal latrace routine (%s).\n",
			TSD_GET(fault_reason,NULL));

		if (TSD_GET(last_operation,-1) >= 0)
			PRINT_ERROR("Last known operation before crash: %s / %s\n", TSD_GET(last_symbol,NULL),
				(!TSD_GET(last_operation,-1) ? "entry" : "exit"));

		PRINT_ERROR("%s", "Exiting immediately.\n");

		if (do_exit)
			*do_exit = 1;
		else
			_exit(EXIT_FAILURE);
	} else {
		TSD_SET(fault_reason, "unknown error");
		PRINT_ERROR("%s", "Warning: signal appeared to be delivered outside of user custom code.\n");

		if (TSD_GET(last_operation,-1) >= 0)
			PRINT_ERROR("Last known operation before crash: %s / %s\n", TSD_GET(last_symbol,NULL),
				(!TSD_GET(last_operation,-1) ? "entry" : "exit"));

		PRINT_ERROR("%s", "Exiting immediately.\n");

		if (do_exit)
			*do_exit = 1;
		else
			_exit(EXIT_FAILURE);
	}

	return;
}


void *address_map[] = { check_names, check_flow_below, free_argbuf, sym_entry, sym_exit,
		check_pid, la_version, la_objopen, la_symbind, la_activity, la_objsearch,
		la_preinit, la_objclose, la_symbind64, pltenter, pltexit,
		lt_stack_process, lt_stack_process_ret };

// XXX: Is there really any value to this?
STATIC void triangulate_pc(unsigned long pc)
{
	char tmpbuf[128], tmpbuf2[128], tmpbuf3[128];
	size_t i, before = 0, after = 0;
	size_t bdist = ~(0), adist = ~(0);

	for (i = 0; i < sizeof(address_map)/sizeof(address_map[0]); i++) {

		if (((unsigned long)address_map[i] >= pc) &&
			((unsigned long)address_map[i] - pc) < adist) {
			adist = (unsigned long)address_map[i] - pc;
			after = i;
		}

		if (((unsigned long)address_map[i] <= pc) &&
			(pc - (unsigned long)address_map[i]) < bdist) {
			bdist = pc - (unsigned long)address_map[i];
			before = i;
		}
	}

	PRINT_ERROR("SANDWICH: %p [%s] <-> %p [%s] <-> %p [%s]\n",
		address_map[before], resolve_sym(address_map[before], 0, tmpbuf, sizeof(tmpbuf), NULL),
		(void *)pc, resolve_sym((void *)pc, 0, tmpbuf2, sizeof(tmpbuf2), NULL),
		address_map[after], resolve_sym(address_map[after], 0, tmpbuf3, sizeof(tmpbuf3), NULL));
}

#ifndef TRANSFORMER_CRASH_PROTECTION_ENHANCED
STATIC
void crash_handler(int signo)
{
	PRINT_ERROR("Warning: caught potentially fatal signal: %d / %ld\n", signo, syscall(SYS_gettid));
	crash_handler_internal(NULL);
}
#else
STATIC
void
crash_handler_si(int signo, siginfo_t *si, void *ucontext)
{
	mcontext_t mcontext;
	const char *more_info = "additional information unavailable";
	unsigned long pc, *fp;
	static int gdb_once = 0;

	if (signo == SIGSEGV) {
		if (si->si_code == SEGV_MAPERR)
			more_info = "address not mapped to object";
		else if (si->si_code == SEGV_ACCERR)
			more_info = "invalid permissions for mapped object";
		else
			more_info = "unknown SIGSEGV violation subtype";
	}

#define PREG(r)	(unsigned long)mcontext.gregs[r]

	mcontext = ((ucontext_t *)ucontext)->uc_mcontext;
	pc = mcontext.gregs[REG_RIP];
	fp = (unsigned long *)mcontext.gregs[REG_RBP];
	PRINT_ERROR("Warning: caught potentially fatal signal: %d (code = %d (%s), addr = %p) / thread %ld; pc=0x%lx\n",
		signo, si->si_code, more_info, si->si_addr, syscall(SYS_gettid), pc);
	PRINT_ERROR("Warning: register dump[ rax = 0x%lx, rbx = 0x%lx, rcx = 0x%lx, rdx = 0x%lx ]\n",
		PREG(REG_RAX), PREG(REG_RBX), PREG(REG_RCX), PREG(REG_RDX));
	PRINT_ERROR("Warning: register dump[ rdi = 0x%lx, rsi = 0x%lx, rbp = 0x%lx, rsp = 0x%lx ]\n",
		PREG(REG_RDI), PREG(REG_RSI), PREG(REG_RBP), PREG(REG_RSP));
	PRINT_ERROR("Warning: register dump[ r8 = 0x%lx, r9 = 0x%lx, r10 = 0x%lx, r11 = 0x%lx ]\n",
		PREG(REG_R8), PREG(REG_R9), PREG(REG_R10), PREG(REG_R11));
	PRINT_ERROR("Warning: register dump[ r12 = 0x%lx, r13 = 0x%lx, r14 = 0x%lx, r15 = 0x%lx ]\n",
		PREG(REG_R12), PREG(REG_R13), PREG(REG_R14), PREG(REG_R15));

	unsigned char *pcb = (unsigned char *)pc;
	PRINT_ERROR("Warning: bytes at instruction pointer: %.2x %.2x %.2x %.2x\n", pcb[0], pcb[1], pcb[2], pcb[3]);
	triangulate_pc(pc);

	size_t level = 0;
	int do_exit = 0;

	while (pc && fp) {
		char tmpbuf[128];
		const char *fname = NULL;

		resolve_sym((void *)pc, 0, tmpbuf, sizeof(tmpbuf), &fname);
		PRINT_ERROR("BACKTRACE / %zu %p <%s> (%s)\n", level++, (void *)pc, tmpbuf, fname);
		pc = fp[1];
		fp = (unsigned long *)fp[0];

		if (pc && !fp) {
			resolve_sym((void *)pc, 0, tmpbuf, sizeof(tmpbuf), &fname);
			PRINT_ERROR("BACKTRACE FINAL (possibly spurious?)/ %zu %p <%s> (%s)\n", level++, (void *)pc, tmpbuf, fname);
		}
	}

	if (gdb_once)
		PRINT_ERROR("%s", "GDB already seems to be launched... skipping prompt.\n");
/*	else {
		size_t sleep_val = 2;
		char tid_buf[16];

		gdb_once = 1;
		PRINT_ERROR("Type anything to spawn GDB (%d / %ld).\n", getpid(), syscall(SYS_gettid));
		getchar();
		snprintf(tid_buf, sizeof(tid_buf), "%ld", syscall(SYS_gettid));
		PRINT_ERROR("Launching GDB and sleeping for %zu seconds...\n", sleep_val);

		switch(fork()) {
			case -1:
				PRINT_ERROR("Could not fork to launch gdb: %s\n", strerror(errno));
				break;
			case 0:
				{
					unsetenv("LIBLDAUDIT_PATH");
					unsetenv("LD_AUDIT");
					execl("/usr/bin/gdb", "/usr/bin/gdb", "attach", tid_buf, NULL);
					perror("execl");
					_exit(-1);
				}
				break;
			default:
				sleep(sleep_val);
				setcontext(ucontext);
				PRINT_ERROR("Error calling setcontext: %s\n", strerror(errno));
				break;
		}

	} */

	crash_handler_internal(&do_exit);

	if (do_exit)
		_exit(EXIT_FAILURE);
}
#endif
#endif

int
setup_crash_handlers(void)
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
