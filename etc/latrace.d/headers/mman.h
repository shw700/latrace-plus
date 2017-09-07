
/* /usr/include/sys/mman.h */

bm_enum mmap_prot {
	PROT_NONE      = 0x0,
	PROT_READ      = 0x1,
	PROT_WRITE     = 0x2,
	PROT_EXEC      = 0x4,
	PROT_SEM       = 0x8,
	PROT_GROWSDOWN = 0x01000000,
	PROT_GROWSUP   = 0x02000000
};

enum_bm mmap_flags {
	MAP_SHARED   =   0x01,
	MAP_PRIVATE  =   0x02,
	MAP_FIXED    =   0x10,
	MAP_ANONYMOUS =  0x20,
	MAP_32BIT     =  0x40,
	MAP_GROWSDOWN =  0x00100,
	MAP_DENYWRITE =  0x00800,
	MAP_EXECUTABLE = 0x01000,
	MAP_LOCKED =     0x02000,
	MAP_NORESERVE =  0x04000,
	MAP_POPULATE =   0x08000,
	MAP_NONBLOCK =   0x10000,
	MAP_STACK =      0x20000,
	MAP_HUGETLB =    0x40000,
};

enum mmap_advice {
	MADV_NORMAL      = 0,
	MADV_RANDOM      = 1,
	MADV_SEQUENTIAL  = 2,
	MADV_WILLNEED    = 3,
	MADV_DONTNEED    = 4,
	MADV_REMOVE      = 9,
	MADV_DONTFORK    = 10,
	MADV_DOFORK      = 11,
	MADV_MERGEABLE   = 12,
	MADV_UNMERGEABLE = 13,
	MADV_HUGEPAGE    = 14,
	MADV_NOHUGEPAGE  = 15,
	MADV_DONTDUMP    = 16,
	MADV_DODUMP      = 17,
	MADV_HWPOISON    = 100
};






extern void *mmap~(void *addr, size_t len, int prot|mmap_prot,
                   int flags|mmap_flags, int fd, __off_t offset);

extern void *mmap64~(void *addr, size_t len, int prot|mmap_prot,
                     int flags|mmap_flags, int fd, long offset);

extern int munmap~(void *addr, size_t len);
extern int mprotect~(void *addr, size_t len, int prot|mmap_prot);
extern int msync~(void *addr, size_t len, int flags);
extern int madvise~(void *addr, size_t len, mmap_advice advice);
extern int posix_madvise(void *addr, size_t len, int advice);
extern int mlock(void *addr, size_t len);
extern int munlock(void *addr, size_t len);
extern int mlockall(int flags);
extern int munlockall(void);
extern int mincore(void *start, size_t len, u_char *vec);

extern void *mremap(void *addr, size_t old_len, size_t new_len,
                     int flags);
extern int remap_file_pages(void *start, size_t size, int prot,
                             size_t pgoff, int flags);
extern int shm_open(char *name, int oflag, mode_t mode);
extern int shm_unlink(char *name);
