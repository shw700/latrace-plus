
/* /usr/include/signal.h */

enum SIGNALS {
	SIGHUP    = 1,
	SIGINT    = 2,
	SIGQUIT   = 3,
	SIGILL    = 4,
	SIGTRAP   = 5,
	SIGABRT   = 6,
	SIGIOT    = 6,
	SIGBUS    = 7,
	SIGFPE    = 8,
	SIGKILL   = 9,
	SIGUSR1   = 10,
	SIGSEGV   = 11,
	SIGUSR2   = 12,
	SIGPIPE   = 13,
	SIGALRM   = 14,
	SIGTERM   = 15,
	SIGSTKFLT = 16,
	SIGCHLD   = 17,
	SIGCONT   = 18,
	SIGSTOP   = 19,
	SIGTSTP   = 20,
	SIGTTIN   = 21,
	SIGTTOU   = 22,
	SIGURG    = 23,
	SIGXCPU   = 24,
	SIGXFSZ   = 25,
	SIGVTALRM = 26,
	SIGPROF   = 27,
	SIGWINCH  = 28,
	SIGIO     = 29,
	SIGPWR    = 30,
	SIGSYS    = 31,
	SIGUNUSED = 31,
	SIGRTMIN  = 32,
	SIGRTMAX  = 32
};

enum SIGNAL_HANDLER {
	SIG_DFL = 0,
	SIG_IGN = 1,
	SIG_ERR = -1
};

enum_bm sa_flag {
	SA_NOCLDSTOP  =  0x00000001,
	SA_NOCLDWAIT  =  0x00000002,
	SA_SIGINFO    =  0x00000004,
	SA_ONSTACK    =  0x08000000,
	SA_RESTART    =  0x10000000,
	SA_NODEFER    =  0x40000000,
	SA_RESETHAND  =  0x80000000
};

enum sigmask_how {
	SIG_BLOCK   = 0,
	SIG_UNBLOCK = 1,
	SIG_SETMASK = 2
};


void*   __sysv_signal(int sig = SIGNALS, void *handler = SIGNAL_HANDLER);
void*   sysv_signal(int sig = SIGNALS, void *handler = SIGNAL_HANDLER);
void*   signal(int sig = SIGNALS, void *handler = SIGNAL_HANDLER);
void*   bsd_signal(int sig = SIGNALS, void *handler = SIGNAL_HANDLER);


int     kill(__pid_t pid, int sig = SIGNALS);
int     killpg(__pid_t pgrp, int sig = SIGNALS);
int     raise~(int sig = SIGNALS);


void*   ssignal(int sig = SIGNALS, void *handler = SIGNAL_HANDLER);
int     gsignal(int sig = SIGNALS);
void    psignal(int sig = SIGNALS, char *s);


int     __sigpause(int sig_or_mask, int is_sig);
int     sigpause(int mask);
int     sigblock(int mask);


int     sigsetmask(int mask);
int     siggetmask();
int     sigemptyset~(sigset_t *set/p);
int     sigfillset~(sigset_t *set/p);
int     sigaddset~(sigset_t *set, int signo = SIGNALS);
int     sigdelset~(sigset_t *set, int signo = SIGNALS);
int     sigismember(const sigset_t *set, int signo = SIGNALS);
int     sigisemptyset(const sigset_t *set);
int     sigandset(sigset_t *dest, const sigset_t *left, const sigset_t *right);
int     sigorset(sigset_t *dest, const sigset_t *left, const sigset_t *right);
int     sigprocmask~(int how=sigmask_how, sigset_t *set, sigset_t *oset/p);
int     sigsuspend~(const sigset_t *mask);
int     sigaction~(SIGNALS signum, struct sigaction *act, struct sigaction *oldact/p);
int     sigpending~(sigset_t *set);
int     sigwait(const sigset_t *set, int *sig);
int     sigwaitinfo(const sigset_t *set, siginfo_t *info);
int     sigtimedwait(const sigset_t *set, sigset_t *info, const struct timespec *timeout);


int     sigqueue(__pid_t pid, int sig = SIGNALS, u_int val);
int     sigvec(int sig = SIGNALS, void *vec, void *ovec);
int     sigreturn(void *scp);
int     siginterrupt(int sig = SIGNALS, int interrupt);
int     sigstack(void *ss, void *oss);
int     sigaltstack(void *ss, void *oss);
int     sighold(int sig = SIGNALS);
int     sigrelse(int sig = SIGNALS);
int     sigignore(int sig = SIGNALS);
void*   sigset(int sig = SIGNALS, void *disp);
int     __libc_current_sigrtmin~();
int     __libc_current_sigrtmax~();
