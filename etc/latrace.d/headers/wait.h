
/* /usr/include/sys/wait.h */


typedef u_int __WAIT_STATUS;
typedef u_int idtype_t;
typedef u_int __id_t;

enum_bm wait_options {
	WNOHANG     = 0x00000001,
	WUNTRACED   = 0x00000002,
	WEXITED     = 0x00000004,
	WCONTINUED  = 0x00000008,
	WNOWAIT     = 0x01000000,
	__WNOTHREAD = 0x20000000,
	__WALL      = 0x40000000,
	__WCLONE    = 0x80000000
};



__pid_t wait(__WAIT_STATUS stat_loc);
pid_t waitpid(pid_t pid, int *stat_loc, int options=wait_options);


int waitid(idtype_t idtype, __id_t id, void *infop, int options);


__pid_t wait3(__WAIT_STATUS stat_loc, int options, void *usage);
__pid_t wait4(__pid_t pid, __WAIT_STATUS stat_loc, int options, void *usage);
