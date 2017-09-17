#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <dlfcn.h>

/*
 * Example of custom user transformers and intercepts that can be used to
 * map out dynamically allocated addresses for subsequent address
 * resolution in latrace output.
 */


#define GET_NEXT_COUNTER(x)	(++counters.n_##x)

struct fn_counters {
	unsigned int n_malloc;
	unsigned int n_calloc;
	unsigned int n_realloc;
	unsigned int n_mmap;
	unsigned int n_strdup;
};

static __thread struct fn_counters counters;


void misc_transformer_init() __attribute__((constructor));
const char *call_lookup_addr(void *addr, char *outbuf, size_t bufsize);

void *(*sym_lookup_addr)(void *) = NULL;
void (*sym_add_address_mapping)(void *, size_t, const char *) = NULL;
void (*sym_remove_address_mapping)(void *, size_t, const char *, int) = NULL;


int latrace_func_to_str_strdup(void **args, size_t argscnt, char *buf, size_t blen, void *retval);
int latrace_func_to_str_calloc(void **args, size_t argscnt, char *buf, size_t blen, void *retval);
int latrace_func_to_str_realloc(void **args, size_t argscnt, char *buf, size_t blen, void *retval);
//int latrace_func_to_str_malloc(void **args, size_t argscnt, void *buf, size_t blen, void *retval);
int latrace_func_to_str_mmap(void **args, size_t argscnt, char *buf, size_t blen, void *retval);
int latrace_func_to_str_munmap(void **args, size_t argscnt, char *buf, size_t blen, void *retval);

void latrace_func_intercept_free(void **args, size_t argscnt, void *retval);
void latrace_func_intercept_malloc(void **args, size_t argscnt, void *retval);


void misc_transformer_init()
{
	fprintf(stderr, "Initializing trackers module (%d)\n", getpid());

	memset(&counters, 0, sizeof(counters));
	sym_lookup_addr = (void *) dlsym(NULL, "lookup_addr");
	sym_add_address_mapping = (void *) dlsym(NULL, "add_address_mapping");
	sym_remove_address_mapping = (void *) dlsym(NULL, "remove_address_mapping");
	return;
}

const char *call_lookup_addr(void *addr, char *outbuf, size_t bufsize)
{
	char *fname = NULL;

	if (!addr)
		return "NULL";

	if (addr && sym_lookup_addr)
		fname = sym_lookup_addr(addr);

	if (fname)
		return fname;

	snprintf(outbuf, bufsize, "%p", addr);
	return outbuf;
}

int latrace_func_to_str_strdup(void **args, size_t argscnt, char *buf, size_t blen, void *retval)
{
	char **result;

	if (!sym_add_address_mapping || !retval || (argscnt != 1))
		return -1;

	result = (char **)retval;

	if (*result) {
		char tokbuf[32];
		unsigned int cnt;

		cnt = GET_NEXT_COUNTER(strdup);
		snprintf(tokbuf, sizeof(tokbuf), "strdup_%u", cnt);
		sym_add_address_mapping(*result, strlen(*result), tokbuf);
		snprintf(buf, blen, "%s (tracking %p)", tokbuf, *result);
		return 0;
	}

	return -1;
}

/*
int latrace_func_to_str_malloc(void **args, size_t argscnt, void *buf, size_t blen, void *retval)
{
	char tokbuf[32];
	void **result;
	size_t *size;
	unsigned int cnt;

	if (!sym_add_address_mapping || !retval || (argscnt != 1))
		return -1;

	size = (size_t *)args[0];
	result = (void **)retval;
	cnt = GET_NEXT_COUNTER(malloc);

	snprintf(tokbuf, sizeof(tokbuf), "malloc_%u", cnt);
	sym_add_address_mapping(*result, *size, tokbuf);
	snprintf(buf, blen, "%s (tracking %p)", tokbuf, *result);
	return 0;
}
*/

void latrace_func_intercept_malloc(void **args, size_t argscnt, void *retval)
{
	char tokbuf[32];
	void **result;
	size_t *size;
	unsigned int cnt;

	if (!sym_add_address_mapping || !retval || (argscnt != 1))
		return;

	size = (size_t *)args[0];
	result = (void **)retval;
	cnt = GET_NEXT_COUNTER(malloc);

	snprintf(tokbuf, sizeof(tokbuf), "malloc_%u", cnt);
	sym_add_address_mapping(*result, *size, tokbuf);
	return;
}

int latrace_func_to_str_calloc(void **args, size_t argscnt, char *buf, size_t blen, void *retval)
{
	char tokbuf[32];
	void **result;
	size_t *nmemb, *size;
	unsigned int cnt;

	if (!sym_add_address_mapping || !retval || (argscnt != 2))
		return -1;

	result = (void **)retval;
	nmemb = (size_t *)args[0];
	size = (size_t *)args[1];

	cnt = GET_NEXT_COUNTER(calloc);
	snprintf(tokbuf, sizeof(tokbuf), "calloc_%u", cnt);
	sym_add_address_mapping(*result, (*nmemb * *size), tokbuf);
	snprintf(buf, blen, "%s (tracking %p)", tokbuf, *result);
	return 0;
}

int latrace_func_to_str_realloc(void **args, size_t argscnt, char *buf, size_t blen, void *retval)
{
	void **result, **ptr;
	size_t *size;

	if (!retval || (argscnt != 2))
		return -1;

	result = (void **)retval;
	ptr = (void **)args[0];
	size = (size_t *)args[1];

	// realloc(NULL, ...) is of course valid
	if (sym_remove_address_mapping && *ptr)
		sym_remove_address_mapping(*ptr, 0, "realloc", 1);

	if (sym_add_address_mapping) {
		char tokbuf[32];
		unsigned int cnt = GET_NEXT_COUNTER(realloc);

		snprintf(tokbuf, sizeof(tokbuf), "realloc_%u", cnt);
		sym_add_address_mapping(*result, *size, tokbuf);
		snprintf(buf, blen, "%s (tracking %p)", tokbuf, *result);
		return 0;
	}

	return -1;
}

void latrace_func_intercept_free(void **args, size_t argscnt, void *retval)
{
	void **ptr;

	if (!sym_remove_address_mapping || !retval || (argscnt != 1))
		return;

	ptr = (void **)args[0];
	sym_remove_address_mapping(*ptr, 0, "free", 1);
	return;
}

int latrace_func_to_str_mmap(void **args, size_t argscnt, char *buf, size_t blen, void *retval)
{
	char tokbuf[32];
	void **addr;
	size_t *size;
	unsigned int cnt;

	if (!sym_add_address_mapping || !retval || (argscnt != 6))
		return -1;

	addr = (void **)retval;
	size = (size_t *)args[1];

	cnt = GET_NEXT_COUNTER(mmap);
	snprintf(tokbuf, sizeof(tokbuf), "mmap_%u", cnt);
	sym_add_address_mapping(*addr, *size, tokbuf);
	snprintf(buf, blen, "%s (tracking %p)", tokbuf, *addr);
	return 0;
}

int latrace_func_to_str_munmap(void **args, size_t argscnt, char *buf, size_t blen, void *retval)
{
	void **addr;
	size_t *size;

	if (!sym_remove_address_mapping || !retval || (argscnt != 2))
		return -1;

	addr = (void **)args[0];
	size = (size_t *)args[1];

	sym_remove_address_mapping(*addr, *size, "munmap", 0);
	return -1;
}
