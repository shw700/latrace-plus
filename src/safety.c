#include <string.h>

#include <execinfo.h>

#include "config.h"


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


void
_print_backtrace(void) {
	void *btbuf[16];
	int nbt;

	nbt = backtrace(btbuf, 16);
	PRINT_ERROR("Backtraced produced: %d addresses\n", nbt);

	backtrace_symbols_fd(btbuf, nbt, 2);
	return;
}
