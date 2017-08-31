#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <dlfcn.h>



void misc_transformer_init() __attribute__((constructor));
const char *call_lookup_addr(void *addr, char *outbuf, size_t bufsize);
void call_lookup_bitmask_by_class(const char *class, unsigned long val, const char *fmt, char *buf, size_t bufsize);


const char *(*sym_lookup_addr)(void *, char *, size_t) = NULL;
char *(*sym_lookup_bitmask_by_class)(void *ignored, const char *, unsigned long, const char *) = NULL;


int latrace_struct_to_str_sigaction(struct sigaction *obj, char *buf, size_t bufsize);


void misc_transformer_init()
{
	fprintf(stderr, "Initializing miscellaneous transformers module.\n");

	sym_lookup_addr = (void *) dlsym(NULL, "lookup_addr");
	sym_lookup_bitmask_by_class = (void *) dlsym(NULL, "lookup_bitmask_by_class");
	return;
}

const char *
get_signal_name(int signo) {

	switch (signo) {
		case SIGHUP:    return "SIGHUP";
		case SIGINT:    return "SIGINT";
		case SIGQUIT:   return "SIGQUIT";
		case SIGILL:    return "SIGILL";
		case SIGTRAP:   return "SIGTRAP";
		case SIGABRT:   return "SIGABRT";
		case SIGBUS:    return "SIGBUS";
		case SIGFPE:    return "SIGFPE";
		case SIGKILL:   return "SIGKILL";
		case SIGUSR1:   return "SIGUSR1";
		case SIGSEGV:   return "SIGSEGV";
		case SIGUSR2:   return "SIGUSR2";
		case SIGPIPE:   return "SIGPIPE";
		case SIGALRM:   return "SIGALRM";
		case SIGTERM:   return "SIGTERM";
		case SIGSTKFLT: return "SIGSTKFLT";
		case SIGCHLD:   return "SIGCHLD";
		case SIGCONT:   return "SIGCONT";
		case SIGSTOP:   return "SIGSTOP";
		case SIGTSTP:   return "SIGTSTP";
		case SIGTTIN:   return "SIGTTIN";
		case SIGTTOU:   return "SIGTTOU";
		case SIGURG:    return "SIGURG";
		case SIGXCPU:   return "SIGXCPU";
		case SIGXFSZ:   return "SIGXFSZ";
		case SIGVTALRM: return "SIGVTALRM";
		case SIGPROF:   return "SIGPROF";
		case SIGWINCH:  return "SIGWINCH";
		case SIGIO:     return "SIGIO";
		case SIGPWR:    return "SIGPWR";
		case SIGSYS:    return "SIGSYS";
		default:
			break;
	}

	return NULL;
}

int
latrace_struct_to_str_sigaction(struct sigaction *obj, char *buf, size_t blen)
{
	char sigbuf[512];
	char flagsbuf[128];
	char handlerbuf[128];
	int s;

	if (obj == NULL)
		return -1;

	memset(flagsbuf, 0, sizeof(flagsbuf));
	memset(sigbuf, 0, sizeof(sigbuf));
	memset(handlerbuf, 0, sizeof(handlerbuf));
	call_lookup_bitmask_by_class("sa_flag", obj->sa_flags, NULL, flagsbuf, sizeof(flagsbuf));

	for (s = 0; s < _NSIG; s++) {

		if (sigismember(&obj->sa_mask, s)) {
			char signo_buf[16];
			const char *signame = get_signal_name(s);

			if (!signame) {
				snprintf(signo_buf, sizeof(signo_buf), "%d", s);
				signame = signo_buf;
			}

			if (sigbuf[0])
				strcat(sigbuf, ",");
			strcat(sigbuf, signame);
		}

	}

	if (obj->sa_flags & SA_SIGINFO)
		snprintf(handlerbuf, sizeof(handlerbuf), "sigaction=%p", obj->sa_sigaction);
	else {
		if (obj->sa_handler == SIG_IGN)
			snprintf(handlerbuf, sizeof(handlerbuf), "handler=SIG_IGN");
		else if (obj->sa_handler == SIG_DFL)
			snprintf(handlerbuf, sizeof(handlerbuf), "handler=SIG_DFL");
		else
			snprintf(handlerbuf, sizeof(handlerbuf), "handler=%p", obj->sa_handler);
	}

	snprintf(buf, blen, "[%s, flags=%s, mask=%s]", handlerbuf, flagsbuf, sigbuf);

	return 0;
}

void
call_lookup_bitmask_by_class(const char *class, unsigned long val, const char *fmt, char *buf, size_t bufsize)
{
	char *maskstr = NULL;

	if (sym_lookup_bitmask_by_class)
		maskstr = sym_lookup_bitmask_by_class(NULL, class, val, fmt);

	if (maskstr) {
		strncpy(buf, maskstr, bufsize);
		free(maskstr);
	} else
		snprintf(buf, bufsize, "0x%lx", val);

	return;
}
