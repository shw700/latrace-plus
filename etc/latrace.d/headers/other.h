/* Miscellaneous definitions (many glibc-internal) */

int __cxa_atexit~(pfn func, void * arg, void * dso_handle);
int __cxa_finalize~(void * d);
int __cxa_guard_acquire(__guard*);
void __cxa_guard_release(__guard*);

void __ctype_init(void);
int __printf_chk~(int flag, const char * format);
int __fprintf_chk~(FILE *__stream, int __flag, char *__format, ...);
int __snprintf_chk~(char *__s, size_t __n, int __flag, size_t __slen, const char *__format, ...);
int ___vsnprintf_chk~(char *s, size_t maxlen, int flags, size_t slen, const char *format, va_list args);
int ___vsnprintf_chk(char *s, size_t maxlen, int flags, size_t slen, const char *format, void *args);
void *__rawmemchr~(const void *__s, int __c);
int __freading~(FILE *__fp);
size_t __fpending~(FILE *__fp);

enum locking_type {
	FSETLOCKING_QUERY = 0,
	FSETLOCKING_INTERNAL,
	FSETLOCKING_BYCALLER
};

int __fsetlocking~(FILE *__fp, int __type=locking_type);

long __fdelt_chk~(long __d);

void __libc_thread_freeres~(void);
int *__errno_location~(void);
int _setjmp(struct __jmp_buf_tag *__env);
int __sigsetjmp~(struct __jmp_buf_tag *__env);

char *__strdup~(const char *__string);

typedef unsigned int wint_t;
typedef unsigned long wctype_t;
wint_t btowc~(int c);
int wctob~(wint_t c);
wctype_t __wctype_l~(const char *property, __locale_t locale);

pfn __nss_lookup_function~(void *nip, char *fnname);
int _nss_files_parse_pwent~(char *line, struct passwd *result, struct parser_data *data, size_t datalen, int *errnop);

int __pthread_key_create~(pthread_key_t *key, pfn *destr);
void *__pthread_getspecific~(pthread_key_t key);
int __pthread_mutex_lock~(pthread_mutex_t *__mutex);
int __pthread_mutex_unlock~(pthread_mutex_t *__mutex);
int *__libc_pthread_init~(unsigned long *ptr, pfn reclaim, const struct pthread_functions *functions);

typedef unsigned long ptrdiff_t;
void* __dynamic_cast~(const void* __src_ptr, const __class_type_info* __src_type, const __class_type_info* __dst_type, ptrdiff_t __src2dst);

int __getpagesize~(void);

long int __strtol_internal~(const char *__nptr, char **__endptr/p, int __base, int __group);
//unsigned long long __strtoull_internal~(__const char *__nptr, char **__endptr, int __base, int __group);
unsigned long __strtoull_internal~(const char *__nptr, char **__endptr, int __base, int __group);

/* glibc / libresolv */
unsigned int __ns_get16~(unsigned char *buf);
unsigned long __ns_get32~(unsigned char *buf);
int __ns_name_unpack~(const u_char *msg, const u_char *eom, const u_char *src, u_char *dst, size_t dstsiz);
int __ns_name_ntop~(const u_char *src, char *dst/p, size_t dstsiz);

int is_selinux_enabled~(void);
int is_selinux_mls_enabled~(void);

PROCTAB* openproc!(int flags/x, ...);
void closeproc~(PROCTAB* PT);
proc_t* readproc!(PROCTAB *PT, proc_t *return_buf);
