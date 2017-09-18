#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <dlfcn.h>



void unix_transformer_init() __attribute__((constructor));
const char *call_lookup_addr(void *addr, char *outbuf, size_t bufsize);
void call_lookup_bitmask_by_class(const char *class, unsigned long val, const char *fmt, char *buf, size_t bufsize);


const char *(*sym_lookup_addr)(void *, char *, size_t) = NULL;
char *(*sym_lookup_bitmask_by_class)(void *ignored, const char *, unsigned long, const char *, char *, size_t) = NULL;


int latrace_struct_to_str_sigaction(struct sigaction *obj, char *buf, size_t bufsize);
int latrace_struct_to_str_sigset_t(sigset_t *obj, char *buf, size_t bufsize);
int latrace_func_to_str_gethostname(void **args, size_t argscnt, char *buf, size_t blen, void *retval);


void unix_transformer_init()
{
	fprintf(stderr, "Initializing UNIX/libc transformers module.\n");

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

int latrace_func_to_str_gethostname(void **args, size_t argscnt, char *buf, size_t blen, void *retval)
{
	int *retint;
	char **name;

        if (!retval || (argscnt != 2))
                return -1;

        retint = (int *)retval;
        name = (char **)args[0];

	if (*retint != 0)
		return -1;

	snprintf(buf, blen, "\"%s\"", *name);
        return 0;
}

int
latrace_struct_to_str_sigset_t(sigset_t *obj, char *buf, size_t blen)
{
	char sigbuf[512];
	int s, inverted = 0;
	size_t sig_tot = 0;

	if (obj == NULL)
		return -1;

	memset(sigbuf, 0, sizeof(sigbuf));

	for (s = 1; s < _NSIG; s++)
		sig_tot += sigismember(obj, s);

	if (_NSIG - sig_tot < 16)
		inverted = 1;

	if (sig_tot == _NSIG-1)
		strcpy(sigbuf, "ALL SIGNALS");
	else if (!sig_tot)
		strcpy(sigbuf, "");
	else {

		for (s = 1; s < _NSIG; s++) {

			if ((!inverted && sigismember(obj, s)) ||
				(inverted && !sigismember(obj, s))) {
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

	}

	if (sigbuf[0] && sigbuf[strlen(sigbuf)-1] == ',')
		sigbuf[strlen(sigbuf)-1] = 0;

	if (inverted)
		snprintf(buf, blen, "![%s]", sigbuf);
	else
		snprintf(buf, blen, "[%s]", sigbuf);

	return 0;
}

int
latrace_struct_to_str_sigaction(struct sigaction *obj, char *buf, size_t blen)
{
	char sigbuf[512];
	char flagsbuf[128];
	char handlerbuf[128];
//	int s;

	if (obj == NULL)
		return -1;

	memset(flagsbuf, 0, sizeof(flagsbuf));
	memset(sigbuf, 0, sizeof(sigbuf));
	memset(handlerbuf, 0, sizeof(handlerbuf));
	call_lookup_bitmask_by_class("sa_flag", obj->sa_flags, NULL, flagsbuf, sizeof(flagsbuf));

	latrace_struct_to_str_sigset_t(&obj->sa_mask, sigbuf, sizeof(sigbuf));

/*	for (s = 1; s < _NSIG; s++) {

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

	} */

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
		maskstr = sym_lookup_bitmask_by_class(NULL, class, val, fmt, buf, bufsize);

	if (!maskstr)
		snprintf(buf, bufsize, "0x%lx", val);

	return;
}
