
/* miscellaneous functions */

int __libc_start_main(pfn main, int argc, void *ubp_av, void *auxvec, pfn init, pfn fini, void *rtld_fini);

/* /usr/include/sys/utsname.h */
int uname(struct utsname *buf);

/* /usr/include/sched.h */
int clone(void *fn, void *child_stack, int flags, void *arg);


/* shm */

enum_bm shmflag {
	SHM_R         = 0400,
	SHM_W         = 0200,
	IPC_CREAT     = 00001000,
	IPC_EXCL      = 00002000,
	SHM_HUGETLB   = 04000,
	SHM_NORESERVE = 010000
};

enum_bm shmctl_op {
	IPC_RMID = 0,
	IPC_SET  = 1,
	IPC_STAT = 2,
	IPC_INFO = 3
};

typedef int key_t;

int shmget(key_t key, size_t size, int shmflg=shmflag);
int shmctl(int shmid, int cmd=shmctl_op, struct shmid_ds *buf);
int shmdt(void *shmaddr);
void *shmat(int shmid, const void *shmaddr, int shmflg);
key_t ftok(const char *pathname, int proj_id);
