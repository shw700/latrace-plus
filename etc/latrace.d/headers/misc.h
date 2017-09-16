
/* miscellaneous functions */

int __libc_start_main(pfn main, int argc, void *ubp_av, void *auxvec, pfn init, pfn fini, void *rtld_fini);

/* /usr/include/sys/utsname.h */
int uname(struct utsname *buf);

/* /usr/include/sched.h */
int clone(void *fn, void *child_stack, int flags, void *arg);
