#include <string.h>

#include "config.h"

#include <libiberty/demangle.h>

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
	size_t *szptr;

	size += sizeof(size_t);

	if (size < 4096)
		size = 4096;

	if ((result = mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0)) == MAP_FAILED)
		return NULL;

	szptr = (size_t *)result;
	*szptr++ = size - sizeof(size_t);
	return (void *)szptr;
}

inline void
safe_free(void *ptr) {
	size_t *szptr = ptr;

	if (!ptr)
		return;

	szptr--;
	munmap(szptr, *szptr+sizeof(size_t));
	return;
}

inline void *
safe_realloc(void *ptr, size_t size) {
	void *result;
	size_t *szptr = ptr;

	result = safe_malloc(size);

	if (!ptr)
		return result;

	szptr--;
	memcpy(result, ptr, *szptr);
	safe_free(ptr);
	return result;
}

inline char *
safe_strdup(const char *s) {
	char *result;
	size_t len;

	len = strlen(s) + 1;

	if (!(result = safe_malloc(len)))
		return NULL;

	memcpy(result, s, len);
	result[len] = 0;
	return result;
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


typedef struct demangle_buffer {
	char *buffer;
	size_t bufsize;
} demangle_buffer_t;

static void
_safe_demangle_cb(const char *buf, size_t bsize, void *opaque)
{
	demangle_buffer_t *dmbuf = opaque;
	size_t left, dlen, maxb;

	if (!dmbuf)
		return;

	dlen = strlen(dmbuf->buffer);
	left = dmbuf->bufsize - (dlen + 1);
	maxb = (left < bsize) ? left : bsize;
	strncpy(&dmbuf->buffer[dlen], buf, maxb);

	return;
}

int
_safe_demangle(const char *symname, char *buf, size_t bufsize) {
	demangle_buffer_t dmbuf;
	int ret;

	memset(&dmbuf, 0, sizeof(dmbuf));
	dmbuf.buffer = buf;
	dmbuf.bufsize = bufsize;
	ret = cplus_demangle_v3_callback(symname, 0, _safe_demangle_cb, &dmbuf);
	return ret;
}
