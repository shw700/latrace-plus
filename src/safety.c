#include <string.h>

#include "config.h"

#ifdef USE_LIBUNWIND
#define UNW_LOCAL_ONLY
#include <libunwind.h>
#else
#include <execinfo.h>
#endif



int glibc_unsafe = 0;


inline void *
xmalloc(size_t size) {
	return malloc(size);
}

inline void *
xrealloc(void *ptr, size_t size) {
	return realloc(ptr, size);
}

inline char *
xstrdup(const char *s) {
	return strdup(s);
}

inline void *
safe_malloc(size_t size) {
	void *result;

	if (size < 4096)
		size = 4096;

	result = mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
	return (result == MAP_FAILED) ? NULL : result;
}

inline void
safe_free(void *ptr) {
	munmap(ptr, 4096);
}


#ifdef USE_LIBUNWIND
void
backtrace_unwind(ucontext_t *start_context)
{
	unw_cursor_t cursor;
	unw_context_t context;
	unw_word_t last_ip = 0, last_sp = 0;
	size_t n = 1;
	pid_t this_thread;

	this_thread = syscall(SYS_gettid);

	if (start_context)
		unw_init_local(&cursor, start_context);
	else {
		unw_getcontext(&context);
		unw_init_local(&cursor, &context);

		if (!unw_step(&cursor)) {
			PRINT_ERROR_SAFE("%s", "Error starting unwound backtrace.\n");
			return;
		}

	}

	while (1) {
		char symname[128];
		unw_word_t ip, sp, off;

		unw_get_reg(&cursor, UNW_REG_IP, &ip);
		unw_get_reg(&cursor, UNW_REG_SP, &sp);

		if (last_ip && last_sp && ip == last_ip && sp == last_sp) {
			PRINT_ERROR_SAFE("%s", "Backtrace seems to be caught in a loop; breaking.\n");
			break;
		}

		last_ip = ip, last_sp = sp;

		memset(symname, 0, sizeof(symname));

		if (unw_get_proc_name(&cursor, symname, sizeof(symname), &off))
			symname[0] = 0;

		if (off)
			PRINT_ERROR_SAFE("BACKTRACE[UW] (%d) / %zu %p <%s+0x%lx>\n", this_thread, n++,
			        (void *)ip, symname, off);
		else
			PRINT_ERROR_SAFE("BACKTRACE[UW] (%d) / %zu %p <%s>\n", this_thread, n++,
			        (void *)ip, symname);

		if (!unw_step(&cursor))
			break;

	}

	return;
}
#endif

void
_print_backtrace(void) {
#ifdef USE_LIBUNWIND
	backtrace_unwind(NULL);
#else
	void *btbuf[16];
	int nbt;

	nbt = backtrace(btbuf, 16);
	PRINT_ERROR_SAFE("Backtrace produced: %d addresses\n", nbt);

	backtrace_symbols_fd(btbuf, nbt, 2);
#endif
	return;
}
