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
