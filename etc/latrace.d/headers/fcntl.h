
/* /usr/include/fcntl.h */

enum_bm open_flags {
	O_RDONLY     = 00000000,
	O_WRONLY     = 00000001,
	O_RDWR       = 00000002,
	O_ACCMODE    = 00000003,
	O_CREAT      = 00000100,
	O_EXCL       = 00000200,
	O_NOCTTY     = 00000400,
	O_TRUNC      = 00001000,
	O_APPEND     = 00002000,
	O_NONBLOCK   = 00004000,
	O_DSYNC      = 00010000,
	FASYNC       = 00020000,
	O_DIRECT     = 00040000,
	O_LARGEFILE  = 00100000,
	O_DIRECTORY  = 00200000,
	O_NOFOLLOW   = 00400000,
	O_NOATIME    = 01000000,
	O_CLOEXEC    = 02000000,
	__O_SYNC     = 04000000,
	O_PATH       = 010000000,
	_O_TMPFILE   = 020000000
};

enum fcntl_cmd {
	F_DUPFD          = 0,
	F_GETFD          = 1,
	F_SETFD          = 2,
	F_GETFL          = 3,
	F_SETFL          = 4,
	F_GETLK          = 5,
	F_SETLK          = 6,
	F_SETLKW         = 7,
	F_SETOWN         = 8,
	F_GETOWN         = 9,
	F_SETSIG         = 10,
	F_GETSIG         = 11,
	F_GETLK64        = 12,
	F_SETLK64        = 13,
	F_SETLKW64       = 14,
	F_SETOWN_EX      = 15,
	F_GETOWN_EX      = 16,
	F_GETOWNER_UIDS  = 17
};


int fcntl~(int fd, int cmd=fcntl_cmd);
int open(char *file, open_flags oflags);
int open64(char *file, int oflag);
int openat(int fd, char *file, int oflag);
int openat64(int fd, char *file, int oflag);
int creat(char *file, __mode_t mode);
int creat64(char *file, __mode_t mode);
int lockf(int fd, int cmd, __off_t len);


int lockf64(int fd, int cmd, __off64_t len);
int posix_fadvise~(int fd, __off_t offset, __off_t len, int advise);
int posix_fadvise64~(int fd, __off64_t offset, __off64_t len, int advise);
int posix_fallocate(int fd, __off_t offset, __off_t len);
int posix_fallocate64(int fd, __off64_t offset, __off64_t len);
