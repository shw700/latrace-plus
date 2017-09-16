#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <dlfcn.h>


void bugcheck_transformer_init() __attribute__((constructor));
const char *call_lookup_addr(void *addr, char *outbuf, size_t bufsize);
const char *(*sym_get_address_mapping)(void *, size_t *, size_t *) = NULL;
const char *(*sym_lookup_addr)(void *, char *, size_t) = NULL;


void latrace_func_intercept_vsnprintf(void **args, size_t argscnt, void *retval);


void bugcheck_transformer_init()
{
	fprintf(stderr, "Initializing bug-checking transformers module.\n");

	sym_lookup_addr = (void *) dlsym(NULL, "lookup_addr");
	sym_get_address_mapping = (void *) dlsym(NULL, "get_address_mapping");
	return;
}

// int vsnprintf(char *str, size_t size, const char *format, va_list ap);
void latrace_func_intercept_vsnprintf(void **args, size_t argscnt, void *retval)
{
	char **str;
	const char *label;
	size_t *size, offset, lsize;
	ssize_t obytes;

	if (retval || (argscnt < 3) || !sym_get_address_mapping)
		return;

        str = (char **)args[0];
	size = (size_t *)args[1];

	if (!(label = sym_get_address_mapping(*str, &lsize, &offset)))
		return;

	obytes = (*str + *size) - (*str - offset + lsize);
	if (obytes > 0) {
#define BOLDMAGENTA "\033[1m\033[35m"      /* Bold Magenta */
#define BOLDGREEN   "\033[1m\033[32m"      /* Bold Green */
#define INVERT  "\033[7m"
#define RESET   "\033[0m"
		fprintf(stderr, "\n%s%sWarning; potential overflow: vsnprintf() called on buffer of size %zu with len = %zu; "
			"possible overflow of %zd bytes%s\n\n",
			BOLDGREEN, INVERT, lsize, *size, obytes, RESET);
	}

        return;
}

