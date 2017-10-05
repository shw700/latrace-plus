enum enum_ctl_op {
	EPOLL_CTL_ADD = 1,
	EPOLL_CTL_DEL = 2,
	EPOLL_CTL_MOD = 3
};

int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout);
int epoll_pwait(int epfd, struct epoll_event *events, int maxevents, int timeout, const sigset_t *sigmask);
int epoll_ctl~(int epfd, enum_ctl_op op, int fd, struct epoll_event *event);
int epoll_create~(int size);
int epoll_create1~(int flags);

typedef unsigned long nfds_t;
int poll(struct pollfd *fds, nfds_t nfds, int timeout);

enum_bm eventfd_flags {
	EFD_SEMAPHORE = 00000001,
	EFD_CLOEXEC   = 02000000,
	EFD_NONBLOCK  = 00004000
};

int eventfd~(unsigned int initval, int flags=eventfd_flags);

int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout);

/* /usr/include/sched.h */
int clone(void *fn, void *child_stack, int flags, void *arg);
int sched_setaffinity(pid_t pid, size_t cpusetsize, const cpu_set_t *mask);
int sched_getaffinity(pid_t pid, size_t cpusetsize, cpu_set_t *mask);

ssize_t lgetxattr~(const char *__path, const char *__name, void *__value, size_t __size);


/* ptrace facility */
enum __ptrace_request {
	PTRACE_TRACEME     = 0,
	PTRACE_PEEKTEXT    = 1,
	PTRACE_PEEKDATA    = 2,
	PTRACE_PEEKUSER    = 3,
	PTRACE_POKETEXT    = 4,
	PTRACE_POKEDATA    = 5,
	PTRACE_POKEUSER    = 6,
	PTRACE_CONT        = 7,
	PTRACE_KILL        = 8,
	PTRACE_SINGLESTEP  = 9,
	PTRACE_GETREGS     = 12,
	PTRACE_SETREGS     = 13,
	PTRACE_GETFPREGS   = 14,
	PTRACE_SETFPREGS   = 15,
	PTRACE_ATTACH      = 16,
	PTRACE_DETACH      = 17,
	PTRACE_GETFPXREGS  = 18,
	PTRACE_SETFPXREGS  = 19,
	PTRACE_SYSCALL     = 24,
	PTRACE_SETOPTIONS  = 0x4200,
	PTRACE_GETEVENTMSG = 0x4201,
	PTRACE_GETSIGINFO  = 0x4202,
	PTRACE_SETSIGINFO  = 0x4203,
	PTRACE_GETREGSET   = 0x4204,
	PTRACE_SETREGSET   = 0x4205,
	PTRACE_SEIZE       = 0x4206,
	PTRACE_INTERRUPT   = 0x4207,
	PTRACE_LISTEN      = 0x4208,
	PTRACE_PEEKSIGINFO = 0x4209,
	PTRACE_GETSIGMASK  = 0x420a,
	PTRACE_SETSIGMASK  = 0x420b,
	PTRACE_SECCOMP_GET_FILTER = 0x420c
};

long ptrace~/p(__ptrace_request request, pid_t pid, void *addr, void *data);
