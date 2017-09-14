/* Miscellaneous definitions (many glibc-internal) */

int __cxa_atexit~(pfn func, void * arg, void * dso_handle);
int __cxa_finalize~(void * d);
int __cxa_guard_acquire~(__guard*);
void __cxa_guard_release~(__guard*);

void __ctype_init(void);
int __printf_chk~(int flag, const char * format);
int __fprintf_chk~(FILE *__stream, int __flag, char *__format, ...);
int __snprintf_chk~(char *__s, size_t __n, int __flag, size_t __slen, const char *__format, ...);
int __vsnprintf_chk~(char *s, size_t maxlen, int flags, size_t slen, const char *format, va_list args);
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

/* pthread internal */
int __pthread_key_create~(pthread_key_t *key, pfn *destr);
void *__pthread_getspecific~(pthread_key_t key);
int __pthread_setspecific~(pthread_key_t key, const void *value);
int __pthread_mutex_lock~(pthread_mutex_t *__mutex);
int __pthread_mutex_unlock~(pthread_mutex_t *__mutex);
int __pthread_once^(pthread_once_t *once_control, pfn init_routine);
int *__libc_pthread_init~(unsigned long *ptr, pfn reclaim, const struct pthread_functions *functions);

/* glibc/ld.so */
void *_dl_allocate_tls~(void *mem);
void *_dl_sym~(void *handle, const char *name, void *who);
struct link_map *_dl_find_dso_for_object~(void *addr);
void **__libc_dl_error_tsd~(void);
void _dl_get_tls_static_info~(size_t *sizep, size_t *alignp);
int __clone(pfn fn, void *__child_stack, int __flags, void *__arg, ...);
int __clone2(pfn fn, void *__child_stack_base, size_t __child_stack_size, int __flags, void *__arg, ...);

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

/* proc */
PROCTAB* openproc!(int flags/x, ...);
void closeproc~(PROCTAB* PT);
proc_t* readproc!(PROCTAB *PT, proc_t *return_buf);


/* editline */
enum el_op {
	EL_PROMPT     = 0,
	EL_TERMINAL   = 1,
	EL_EDITOR     = 2,
	EL_SIGNAL     = 3,
	EL_BIND       = 4,
	EL_TELLTC     = 5,
	EL_SETTC      = 6,
	EL_ECHOTC     = 7,
	EL_SETTY      = 8,
	EL_ADDFN      = 9,
	EL_HIST       = 10,
	EL_EDITMODE   = 11,
	EL_RPROMPT    = 12,
	EL_GETCFN     = 13,
	EL_CLIENTDATA = 14,
	EL_UNBUFFERED = 15,
	EL_PREP_TERM  = 16,
	EL_GETTC      = 17,
	EL_GETFP      = 18,
	EL_SETFP      = 19,
	EL_REFRESH    = 20
};

EditLine *el_init(const char *prog, FILE *fin, FILE *fout, FILE *ferr);
int el_get!(EditLine *e, int op=el_op, ...);
int el_set!(EditLine *e, int op=el_op, ...);
const char *el_gets!(EditLine *e, int *count);
int el_source~(EditLine *e, const char *file);
int el_getc~(EditLine *e, char *ch/p);
void el_reset~(EditLine *e);
void el_end~(EditLine *e);

History *history_init~(void);
int history~(History *h, HistEvent *ev, int op, ...);
void history_end~(History *h);


/* regex */
enum_bm regcomp_flags {
	REG_EXTENDED = 1,
	REG_ICASE    = 2,
	REG_NEWLINE  = 4,
	REG_NOSUB    = 8
};

int regcomp(regex_t *preg, const char *regex, int cflags=regcomp_flags);
int regexec(const regex_t *preg, const char *string, size_t nmatch, regmatch_t *pmatch, int eflags);
void regfree!(regex_t *preg);

/* libbsd */
size_t strlcpy~(char *dst/p, const char *src, size_t siz);

/* zlib */
typedef void *z_streamp;
int inflateInit_(z_streamp strm, const char *version, int stream_size);
int inflateInit2_(z_streamp strm, int windowBits, const char *version, int stream_size);
int inflateReset(z_streamp strm);
int inflateReset2(z_streamp strm, int windowBits);
int inflateResetKeep(z_streamp strm);
