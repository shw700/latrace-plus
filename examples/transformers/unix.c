#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <dlfcn.h>



void unix_transformer_init() __attribute__((constructor));
const char *call_lookup_addr(void *addr, char *outbuf, size_t bufsize);
void call_lookup_bitmask_by_class(const char *class, unsigned long val, const char *fmt, char *buf, size_t bufsize);
void call_lookup_constant_by_class(const char *class, unsigned long val, const char *fmt, char *buf, size_t bufsize);


const char *(*sym_lookup_addr)(void *, char *, size_t) = NULL;
char *(*sym_lookup_bitmask_by_class)(void *ignored, const char *, unsigned long, const char *, char *, size_t) = NULL;
char *(*sym_lookup_constant_by_class)(void *ignored, const char *, unsigned long, const char *, char *, size_t) = NULL;


int latrace_struct_to_str_sigaction(struct sigaction *obj, char *buf, size_t bufsize);
int latrace_struct_to_str_sigset_t(sigset_t *obj, char *buf, size_t bufsize);
int latrace_func_to_str_gethostname(void **args, size_t argscnt, char *buf, size_t blen, void *retval);
int latrace_func_to_str_getaddrinfo(void **args, size_t argscnt, char *buf, size_t blen, void *retval);
int latrace_func_to_str_waitpid(void **args, size_t argscnt, char *buf, size_t blen, void *retval);


void unix_transformer_init()
{
	fprintf(stderr, "Initializing UNIX/libc transformers module.\n");

	sym_lookup_addr = (void *) dlsym(NULL, "lookup_addr");
	sym_lookup_bitmask_by_class = (void *) dlsym(NULL, "lookup_bitmask_by_class");
	sym_lookup_constant_by_class = (void *) dlsym(NULL, "lookup_constant_by_class");
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

int latrace_func_to_str_getaddrinfo(void **args, size_t argscnt, char *buf, size_t blen, void *retval)
{
	struct addrinfo ***ai, *aiptr;
	struct sockaddr_in *s_in;
	char ai_family_buf[64], ai_socktype_buf[64], ai_protocol_buf[64], ai_flags_buf[128], ai_addr_buf[32];
	char *canon;
	int *retint;
	size_t aicnt = 0, nleft;
	int cnt = 0;

        if (!retval || (argscnt != 4))
                return -1;

        retint = (int *)retval;
//        node = (char **)args[0];
 //       service = (char **)args[1];
        ai = (struct addrinfo ***)args[3];

	if (*retint != 0)
		return -1;

	if (!*ai || !**ai)
		return -1;

	aiptr = **ai;

	while (aiptr) {
		aiptr = aiptr->ai_next;
		aicnt++;
	}

	if (!aicnt) {
		snprintf(buf, blen, "%d (%zu total results)", *retint, aicnt);
		return 0;
	}

	snprintf(buf, blen, "%d (%zu total results) { ", *retint, aicnt);

	nleft = blen - strlen(buf);
	aiptr = **ai;

	while ((nleft > 0) && aiptr) {
		char *prefix = "";
		memset(ai_addr_buf, 0, sizeof(ai_addr_buf));
		s_in = (struct sockaddr_in *)aiptr->ai_addr;

		if (!inet_ntop(s_in->sin_family, aiptr->ai_addr, ai_addr_buf, sizeof(ai_addr_buf))) {
			snprintf(ai_addr_buf, sizeof(ai_addr_buf), "[unknown addr type(%u bytes)]", aiptr->ai_addrlen);
		}

		call_lookup_constant_by_class("PF_TYPE", aiptr->ai_family, NULL, ai_family_buf, sizeof(ai_family_buf));
		call_lookup_constant_by_class("SOCK_TYPE", aiptr->ai_socktype, NULL, ai_socktype_buf, sizeof(ai_socktype_buf));

		if ((aiptr->ai_family == AF_INET) || (aiptr->ai_family == AF_INET6))
			call_lookup_constant_by_class("SOCK_PROTOCOL_INET", aiptr->ai_protocol, NULL, ai_protocol_buf, sizeof(ai_protocol_buf));
		else
			snprintf(ai_protocol_buf, sizeof(ai_protocol_buf), "0x%x", aiptr->ai_protocol);

		call_lookup_bitmask_by_class("ai_flags", aiptr->ai_flags, NULL, ai_flags_buf, sizeof(ai_flags_buf));
		canon = aiptr->ai_canonname ? aiptr->ai_canonname : "[none]";

		if (cnt)
			prefix = ",  ";

		snprintf(&(buf[strlen(buf)]), nleft, "%s%d(addr = %s, family = %s, type = %s, protocol = %s, canonical = %s, flags = %s)",
			prefix, cnt+1, ai_addr_buf, ai_family_buf, ai_socktype_buf, ai_protocol_buf,
			canon, ai_flags_buf);
		nleft = blen - strlen(buf);
		aiptr = aiptr->ai_next;
		cnt++;
	}

	snprintf(&(buf[strlen(buf)]), nleft, " }");
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

void
call_lookup_constant_by_class(const char *class, unsigned long val, const char *fmt, char *buf, size_t bufsize)
{
	char *conststr = NULL;

	if (sym_lookup_constant_by_class)
		conststr = sym_lookup_constant_by_class(NULL, class, val, fmt, buf, bufsize);

	if (!conststr)
		snprintf(buf, bufsize, "0x%lx", val);

	return;
}

#define BOOL_TO_STR(x)	((x != 0) ? "true" : "false")

/* Only the return value requires massaging */
int latrace_func_to_str_waitpid(void **args, size_t argscnt, char *buf, size_t blen, void *retval)
{
	char exitbuf[128], sigbuf[128], auxbuf[128], *bptr;
	int **status, *retpid;

        if (!retval || (argscnt != 3))
                return -1;

	retpid = (int *)retval;
        status = (int **)args[1];

	if ((*status == NULL) || (*retpid == -1))
		return -1;

	exitbuf[0] = sigbuf[0] = auxbuf[0] = 0;

	if (WIFEXITED(**status)) {
		snprintf(exitbuf, sizeof(exitbuf), "EXITED=true/EXITSTATUS=%d ", WEXITSTATUS(**status));
	} else if (WIFSIGNALED(status)) {
		const char *signame = get_signal_name(WTERMSIG(**status));
		char snbuf[32];

		if (!signame) {
			sprintf(snbuf, "%d", WTERMSIG(**status));
			signame = snbuf;
		}

		snprintf(sigbuf, sizeof(sigbuf), "SIGNALED=true/TERMSIG=%s ", signame);
		#ifdef WCOREDUMP
			snprintf(&(exitbuf[strlen(exitbuf)], sizeof(exitbuf)-strlen(exitbuf), " WCOREDUMP=%s ",
				BOOL_TO_STR(WCOREDUMP(**status))));
		#endif
	}

	if (WIFSTOPPED(**status)) {
		const char *signame;
		char snbuf[64];
		int stopsig, trace_sys_good;

		stopsig = WSTOPSIG(**status);
		trace_sys_good = stopsig | 0x80;
		stopsig &= ~(0x80);
		signame = get_signal_name(stopsig);

		if (!signame) {
			if (!trace_sys_good)
				snprintf(snbuf, sizeof(snbuf), "%d", stopsig);
			else
				snprintf(snbuf, sizeof(snbuf), "0x80|%d", stopsig);

		} else {
			if (!trace_sys_good)
				snprintf(snbuf, sizeof(snbuf), "%s", signame);
			else
				snprintf(snbuf, sizeof(snbuf), "0x80|%s", signame);
		}

		snprintf(auxbuf, sizeof(auxbuf), "STOPPED=true/STOPSIG=%s ", snbuf);
	}

	if (WIFCONTINUED(**status)) {
		snprintf(&auxbuf[strlen(auxbuf)], sizeof(auxbuf)-strlen(auxbuf), "CONTINUED=true");
	}

//	snprintf(buf, blen, "%d [status=0x%x (%s%s%s)]", *retpid, **status, exitbuf, sigbuf, auxbuf);
	snprintf(buf, blen-2, "%d [status=0x%x (%s%s%s", *retpid, **status, exitbuf, sigbuf, auxbuf);
	bptr = buf + strlen(buf) - 1;

	while ((bptr > buf) && (*bptr == ' '))
		*bptr-- = 0;

	strcpy(bptr+1, ")]");
        return 0;
}
