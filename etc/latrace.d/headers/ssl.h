
/* /usr/include/openssl/ssl.h (and friends) */

enum bio_ctrl_cmd { BIO_CTRL_RESET=1, BIO_CTRL_EOF=2, BIO_CTRL_INFO=3, BIO_CTRL_SET=4, BIO_CTRL_GET=5, BIO_CTRL_PUSH=6, BIO_CTRL_POP=7, BIO_CTRL_GET_CLOSE=8, BIO_CTRL_SET_CLOSE=9, BIO_CTRL_PENDING=10, BIO_CTRL_FLUSH=11, BIO_CTRL_DUP=12, BIO_CTRL_WPENDING=13, BIO_CTRL_SET_CALLBACK=14, BIO_CTRL_GET_CALLBACK=15, BIO_CTRL_SET_FILENAME=30, BIO_CTRL_DGRAM_CONNECT=31, BIO_CTRL_DGRAM_SET_CONNECTED=32, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT=33, BIO_CTRL_DGRAM_GET_RECV_TIMEOUT=34, BIO_CTRL_DGRAM_SET_SEND_TIMEOUT=35, BIO_CTRL_DGRAM_GET_SEND_TIMEOUT=36, BIO_CTRL_DGRAM_GET_RECV_TIMER_EXP=37, BIO_CTRL_DGRAM_GET_SEND_TIMER_EXP=38, BIO_CTRL_DGRAM_MTU_DISCOVER=39, BIO_CTRL_DGRAM_QUERY_MTU=40, BIO_CTRL_DGRAM_GET_FALLBACK_MTU=47, BIO_CTRL_DGRAM_GET_MTU=41, BIO_CTRL_DGRAM_SET_MTU=42, BIO_CTRL_DGRAM_MTU_EXCEEDED=43, BIO_CTRL_DGRAM_GET_PEER=46, BIO_CTRL_DGRAM_SET_PEER=44, BIO_CTRL_DGRAM_SET_NEXT_TIMEOUT=45, BIO_CTRL_DGRAM_SET_DONT_FRAG=48, BIO_CTRL_DGRAM_GET_MTU_OVERHEAD=49, BIO_CTRL_DGRAM_SCTP_SET_IN_HANDSHAKE=50, BIO_CTRL_DGRAM_SCTP_ADD_AUTH_KEY=51, BIO_CTRL_DGRAM_SCTP_NEXT_AUTH_KEY=52, BIO_CTRL_DGRAM_SCTP_AUTH_CCS_RCVD=53, BIO_CTRL_DGRAM_SCTP_GET_SNDINFO=60, BIO_CTRL_DGRAM_SCTP_SET_SNDINFO=61, BIO_CTRL_DGRAM_SCTP_GET_RCVINFO=62, BIO_CTRL_DGRAM_SCTP_SET_RCVINFO=63, BIO_CTRL_DGRAM_SCTP_GET_PRINFO=64, BIO_CTRL_DGRAM_SCTP_SET_PRINFO=65, BIO_CTRL_DGRAM_SCTP_SAVE_SHUTDOWN=70, BIO_C_SET_CONNECT=100, BIO_C_DO_STATE_MACHINE=101, BIO_C_SET_NBIO=102, BIO_C_SET_PROXY_PARAM=103, BIO_C_SET_FD=104, BIO_C_GET_FD=105, BIO_C_SET_FILE_PTR=106, BIO_C_GET_FILE_PTR=107, BIO_C_SET_FILENAME=108, BIO_C_SET_SSL=109, BIO_C_GET_SSL=110, BIO_C_SET_MD=111, BIO_C_GET_MD=112, BIO_C_GET_CIPHER_STATUS=113, BIO_C_SET_BUF_MEM=114, BIO_C_GET_BUF_MEM_PTR=115, BIO_C_GET_BUFF_NUM_LINES=116, BIO_C_SET_BUFF_SIZE=117, BIO_C_SET_ACCEPT=118, BIO_C_SSL_MODE=119, BIO_C_GET_MD_CTX=120, BIO_C_GET_PROXY_PARAM=121, BIO_C_SET_BUFF_READ_DATA=122, BIO_C_GET_CONNECT=123, BIO_C_GET_ACCEPT=124, BIO_C_SET_SSL_RENEGOTIATE_BYTES=125, BIO_C_GET_SSL_NUM_RENEGOTIATES=126, BIO_C_SET_SSL_RENEGOTIATE_TIMEOUT=127, BIO_C_FILE_SEEK=128, BIO_C_GET_CIPHER_CTX=129, BIO_C_SET_BUF_MEM_EOF_RETURN=130, BIO_C_SET_BIND_MODE=131, BIO_C_GET_BIND_MODE=132, BIO_C_FILE_TELL=133, BIO_C_GET_SOCKS=134, BIO_C_SET_SOCKS=135, BIO_C_SET_WRITE_BUF_SIZE=136, BIO_C_GET_WRITE_BUF_SIZE=137, BIO_C_MAKE_BIO_PAIR=138, BIO_C_DESTROY_BIO_PAIR=139, BIO_C_GET_WRITE_GUARANTEE=140, BIO_C_GET_READ_REQUEST=141, BIO_C_SHUTDOWN_WR=142, BIO_C_NREAD0=143, BIO_C_NREAD=144, BIO_C_NWRITE0=145, BIO_C_NWRITE=146, BIO_C_RESET_READ_REQUEST=147, BIO_C_SET_MD_CTX=148, BIO_C_SET_PREFIX=149, BIO_C_GET_PREFIX=150, BIO_C_SET_SUFFIX=151, BIO_C_GET_SUFFIX=152, BIO_C_SET_EX_ARG=153, BIO_C_GET_EX_ARG=154 };

enum bio_type { BIO_TYPE_NONE=0, BIO_TYPE_MEM=0x401, BIO_TYPE_FILE=0x402, BIO_TYPE_FD=0x504, BIO_TYPE_SOCKET=0x505, BIO_TYPE_NULL=0x406, BIO_TYPE_SSL=0x207, BIO_TYPE_MD=0x208, BIO_TYPE_BUFFER=0x209, BIO_TYPE_CIPHER=0x20a, BIO_TYPE_BASE64=0x20b, BIO_TYPE_CONNECT=0x50c, BIO_TYPE_ACCEPT=0x50d, BIO_TYPE_PROXY_CLIENT=0x20e, BIO_TYPE_PROXY_SERVER=0x20f, BIO_TYPE_NBIO_TEST=0x210, BIO_TYPE_NULL_FILTER=0x211, BIO_TYPE_BER=0x212, BIO_TYPE_BIO=0x413, BIO_TYPE_LINEBUFFER=0x214, BIO_TYPE_DGRAM=0x515, BIO_TYPE_DGRAM_SCTP=0x518, BIO_TYPE_ASN1=0x216, BIO_TYPE_COMP=0x217, BIO_TYPE_DESCRIPTOR=0x0100, BIO_TYPE_FILTER=0x0200, BIO_TYPE_SOURCE_SINK=0x0400 };

enum openssl_ctrl_cmd { SSL_CTRL_NEED_TMP_RSA=1, SSL_CTRL_SET_TMP_RSA=2, SSL_CTRL_SET_TMP_DH=3, SSL_CTRL_SET_TMP_ECDH=4, SSL_CTRL_SET_TMP_RSA_CB=5, SSL_CTRL_SET_TMP_DH_CB=6, SSL_CTRL_SET_TMP_ECDH_CB=7, SSL_CTRL_GET_SESSION_REUSED=8, SSL_CTRL_GET_CLIENT_CERT_REQUEST=9, SSL_CTRL_GET_NUM_RENEGOTIATIONS=10, SSL_CTRL_CLEAR_NUM_RENEGOTIATIONS=11, SSL_CTRL_GET_TOTAL_RENEGOTIATIONS=12, SSL_CTRL_GET_FLAGS=13, SSL_CTRL_EXTRA_CHAIN_CERT=14, SSL_CTRL_SET_MSG_CALLBACK=15, SSL_CTRL_SET_MSG_CALLBACK_ARG=16, SSL_CTRL_SET_MTU=17, SSL_CTRL_SESS_NUMBER=20, SSL_CTRL_SESS_CONNECT=21, SSL_CTRL_SESS_CONNECT_GOOD=22, SSL_CTRL_SESS_CONNECT_RENEGOTIATE=23, SSL_CTRL_SESS_ACCEPT=24, SSL_CTRL_SESS_ACCEPT_GOOD=25, SSL_CTRL_SESS_ACCEPT_RENEGOTIATE=26, SSL_CTRL_SESS_HIT=27, SSL_CTRL_SESS_CB_HIT=28, SSL_CTRL_SESS_MISSES=29, SSL_CTRL_SESS_TIMEOUTS=30, SSL_CTRL_SESS_CACHE_FULL=31, SSL_CTRL_OPTIONS=32, SSL_CTRL_MODE=33, SSL_CTRL_GET_READ_AHEAD=40, SSL_CTRL_SET_READ_AHEAD=41, SSL_CTRL_SET_SESS_CACHE_SIZE=42, SSL_CTRL_GET_SESS_CACHE_SIZE=43, SSL_CTRL_SET_SESS_CACHE_MODE=44, SSL_CTRL_GET_SESS_CACHE_MODE=45, SSL_CTRL_GET_MAX_CERT_LIST=50, SSL_CTRL_SET_MAX_CERT_LIST=51, SSL_CTRL_SET_MAX_SEND_FRAGMENT=52, SSL_CTRL_SET_TLSEXT_SERVERNAME_CB=53, SSL_CTRL_SET_TLSEXT_SERVERNAME_ARG=54, SSL_CTRL_SET_TLSEXT_HOSTNAME=55, SSL_CTRL_SET_TLSEXT_DEBUG_CB=56, SSL_CTRL_SET_TLSEXT_DEBUG_ARG=57, SSL_CTRL_GET_TLSEXT_TICKET_KEYS=58, SSL_CTRL_SET_TLSEXT_TICKET_KEYS=59, SSL_CTRL_SET_TLSEXT_OPAQUE_PRF_INPUT=60, SSL_CTRL_SET_TLSEXT_OPAQUE_PRF_INPUT_CB=61, SSL_CTRL_SET_TLSEXT_OPAQUE_PRF_INPUT_CB_ARG=62, SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB=63, SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB_ARG=64, SSL_CTRL_SET_TLSEXT_STATUS_REQ_TYPE=65, SSL_CTRL_GET_TLSEXT_STATUS_REQ_EXTS=66, SSL_CTRL_SET_TLSEXT_STATUS_REQ_EXTS=67, SSL_CTRL_GET_TLSEXT_STATUS_REQ_IDS=68, SSL_CTRL_SET_TLSEXT_STATUS_REQ_IDS=69, SSL_CTRL_GET_TLSEXT_STATUS_REQ_OCSP_RESP=70, SSL_CTRL_SET_TLSEXT_STATUS_REQ_OCSP_RESP=71, SSL_CTRL_SET_TLSEXT_TICKET_KEY_CB=72, SSL_CTRL_SET_TLS_EXT_SRP_USERNAME_CB=75, SSL_CTRL_SET_SRP_VERIFY_PARAM_CB=76, SSL_CTRL_SET_SRP_GIVE_CLIENT_PWD_CB=77, SSL_CTRL_SET_SRP_ARG=78, SSL_CTRL_SET_TLS_EXT_SRP_USERNAME=79, SSL_CTRL_SET_TLS_EXT_SRP_STRENGTH=80, SSL_CTRL_SET_TLS_EXT_SRP_PASSWORD=81, SSL_CTRL_TLS_EXT_SEND_HEARTBEAT=85, SSL_CTRL_GET_TLS_EXT_HEARTBEAT_PENDING=86, SSL_CTRL_SET_TLS_EXT_HEARTBEAT_NO_REQUESTS=87, SSL_CTRL_GET_RI_SUPPORT=76, SSL_CTRL_CLEAR_OPTIONS=77, SSL_CTRL_CLEAR_MODE=78, SSL_CTRL_GET_EXTRA_CHAIN_CERTS=82, SSL_CTRL_CLEAR_EXTRA_CHAIN_CERTS=83, SSL_CTRL_CHAIN=88, SSL_CTRL_CHAIN_CERT=89, SSL_CTRL_GET_CURVES=90, SSL_CTRL_SET_CURVES=91, SSL_CTRL_SET_CURVES_LIST=92, SSL_CTRL_GET_SHARED_CURVE=93, SSL_CTRL_SET_ECDH_AUTO=94, SSL_CTRL_SET_SIGALGS=97, SSL_CTRL_SET_SIGALGS_LIST=98, SSL_CTRL_CERT_FLAGS=99, SSL_CTRL_CLEAR_CERT_FLAGS=100, SSL_CTRL_SET_CLIENT_SIGALGS=101, SSL_CTRL_SET_CLIENT_SIGALGS_LIST=102, SSL_CTRL_GET_CLIENT_CERT_TYPES=103, SSL_CTRL_SET_CLIENT_CERT_TYPES=104, SSL_CTRL_BUILD_CERT_CHAIN=105, SSL_CTRL_SET_VERIFY_CERT_STORE=106, SSL_CTRL_SET_CHAIN_CERT_STORE=107, SSL_CTRL_GET_PEER_SIGNATURE_NID=108, SSL_CTRL_GET_SERVER_TMP_KEY=109, SSL_CTRL_GET_RAW_CIPHERLIST=110, SSL_CTRL_GET_EC_POINT_FORMATS=111, SSL_CTRL_GET_CHAIN_CERTS=115, SSL_CTRL_SELECT_CURRENT_CERT=116, SSL_CTRL_SET_CURRENT_CERT=117, SSL_CTRL_CHECK_PROTO_VERSION=119 };

enum_bm crypto_lock_mode {
	CRYPTO_LOCK   = 0x01,
	CRYPTO_UNLOCK = 0x02,
	CRYPTO_READ   = 0x04,
	CRYPTO_WRITE  = 0x08
};

enum ssl_version {
	SSL2_VERSION = 0x0002,
	SSL3_VERSION = 0x0300,
	TLS1_VERSION = 0x0301,
	TLS1_1_VERSION = 0x0302,
	TLS1_2_VERSION = 0x0303
};

enum_bm ssl_state {
	SSL_ST_RENEGOTIATE = 0x4004,
	SSL_ST_BEFORE  = 0x4000,
	SSL_ST_INIT    = 0x3000,
	SSL_ST_CONNECT = 0x1000,
	SSL_ST_ACCEPT  = 0x2000,
	SSL_ST_OK      = 0x03,
	SSL_ST_ERR     = 0x05
};

enum ssl_error_no {
	SSL_ERROR_NONE             = 0,
	SSL_ERROR_SSL              = 1,
	SSL_ERROR_WANT_READ        = 2,
	SSL_ERROR_WANT_WRITE       = 3,
	SSL_ERROR_WANT_X509_LOOKUP = 4,
	SSL_ERROR_SYSCALL          = 5,
	SSL_ERROR_ZERO_RETURN      = 6,
	SSL_ERROR_WANT_CONNECT     = 7,
	SSL_ERROR_WANT_ACCEPT      = 8
};

enum bio_new_flags {
	BIO_NOCLOSE = 0x00,
	BIO_CLOSE   = 0x01,
	BIO_FP_TEXT = 0x10
};


int SSL_library_init!(void);
int SSL_CTX_set_cipher_list(SSL_CTX *ctx, const char *str);
int SSL_set_cipher_list(void *ssl, const char *str);
void SSL_set_connect_state~(SSL *s);
int SSL_accept(void *ssl);
int SSL_connect(void *ssl);
SSL *SSL_new(SSL_CTX *ctx);
void SSL_free!(SSL *ssl);
int SSL_shutdown~(SSL *s);
int SSL_clear~(SSL *ssl);
void SSL_CTX_free(void *ctx);
void *SSL_CTX_new(void *method);
void SSL_CTX_set_verify(void *ctx, int mode, void *verify_cb);
void SSL_CTX_set_verify_depth~(SSL_CTX *ctx, int depth);
int SSL_CTX_load_verify_locations(void *ctx, const char *CAfile, const char *CApath);
long SSL_CTX_ctrl(void *ctx, int cmd = openssl_ctrl_cmd, long larg, void *parg);
int SSL_CTX_set_default_verify_paths(void *ctx);
const SSL_METHOD *SSLv23_client_method~(void);

SSL_SESSION *SSL_SESSION_new(void);
void SSL_SESSION_free(SSL_SESSION *session);
SSL_SESSION *SSL_get_session~(const SSL *ssl);
void OPENSSL_cleanse~(void *ptr, size_t len);
void OPENSSL_config(const char *config_name);
void OPENSSL_no_config(void);
ssl_version SSL_version~(const SSL *s);
int SSL_CTX_check_private_key(void *ctx);
int SSL_check_private_key(void *ssl);
void CRYPTO_lock~(int mode=crypto_lock_mode, int n, const char *file, int line);
int SSL_read(void *ssl, void *buf, int num);
int SSL_write!(SSL *ssl, void *buf, int num);
int SSL_get_fd~(const SSL *ssl);
int SSL_get_rfd(void *ssl);
int SSL_get_wfd(void *ssl);
const COMP_METHOD *SSL_get_current_compression~(SSL *s);
void *SSL_COMP_get_compression_methods~(void);

void *CRYPTO_malloc~(int num, const char *file, int line);
void CRYPTO_free~(void *ptr);
int CRYPTO_set_mem_functions~(pfn m, pfn r, pfn f);
int CRYPTO_add_lock~(int *pointer, int amount, int type, const char *file, int line);
int CRYPTO_is_mem_check_on~(void);
void CRYPTO_THREADID_current~(CRYPTO_THREADID *id);
void CRYPTO_THREADID_set_pointer~(CRYPTO_THREADID *id, void *ptr);
unsigned long CRYPTO_THREADID_hash~/x(const CRYPTO_THREADID *id);
int CRYPTO_THREADID_cmp~(const CRYPTO_THREADID *a, const CRYPTO_THREADID *b);

int SSL_CTX_use_PrivateKey(void *ctx, void *pkey);
int SSL_use_PrivateKey_file(void *ssl, const char *file, int type);
int SSL_CTX_use_certificate(void *ctx, void *x);
int=ssl_state SSL_state~(SSL *ssl);
int SSL_pending~(const SSL *ssl);

const char *SSL_CIPHER_get_name~(const SSL_CIPHER *c);
const SSL_CIPHER *SSL_get_current_cipher(const SSL *s);

void OPENSSL_add_all_algorithms_noconf!(void);

void ERR_load_SSL_strings!(void);
void ERR_load_crypto_strings!(void);
void SSL_load_error_strings!(void);
void ERR_free_strings!(void);
int=ssl_error_no SSL_get_error~(const SSL *ssl, int ret);
ERR_STATE *ERR_get_state~(void);
void ERR_add_error_data~(int num, ...);
void ERR_clear_error~(void);
long ERR_get_error(void);
const char *ERR_func_error_string~(unsigned long e);
//void ERR_put_error~(int lib, int func, int reason, const char *file, int line);

BIO *BIO_new~(BIO_method *type);
int BIO_free~(BIO *a);
long BIO_ctrl(void *bp, int cmd = bio_ctrl_cmd, long larg, void*parg);
int BIO_read~(BIO *b, void *buf, int len);
int BIO_gets~(BIO *b, char *buf, int size);
int BIO_write~(BIO *b, const void *buf, int len);
int BIO_puts~(BIO *b, const char *buf);
int BIO_printf!(void *bio, const char *format, ...);
int BIO_snprintf~(char *buf/p, size_t n, const char *format, ...);
BIO *BIO_new_socket~(int sock, int close_flag);
BIO *BIO_new_fp~(FILE *stream, int flags=bio_new_flags);
BIO *BIO_new_file~(const char *filename, const char *mode);
BIO_METHOD *BIO_s_file~(void);

unsigned long BIO_number_written~(BIO *bio);
unsigned long BIO_number_read~(BIO *bio);
void *BIO_find_type(void *b, int bio_type = bio_type);
int BIO_dump_indent!(BIO *b, const char *s, int len, int indent);
int BIO_dump_indent_fp(void *fp, const char *s, int len, int indent);
BIO *SSL_get_rbio~(const SSL *ssl);
BIO *SSL_get_wbio~(const SSL *ssl);
void SSL_set_bio~(SSL *ssl, BIO *rbio, BIO *wbio);

void *PEM_read_bio_PrivateKey(void *bp, void **x, void *cb, void *u);
void *PEM_read_bio_X509_AUX(void *bp, void **x, void *cb, void *u);

EVP_KEY *EVP_PKEY_new~(void);
void EVP_PKEY_free~(EVP_PKEY *key);
int EVP_PKEY_bits~(EVP_PKEY *pkey);

EVP_PKEY_CTX *EVP_PKEY_CTX_new~(EVP_PKEY *pkey, ENGINE *e);
void EVP_PKEY_CTX_free~(EVP_PKEY_CTX *ctx);
EVP_PKEY_CTX *EVP_PKEY_CTX_dup~(EVP_PKEY_CTX *ctx);
int EVP_PKEY_asn1_get_count~(void);
const EVP_PKEY_ASN1_METHOD *EVP_PKEY_asn1_get0~(int idx);

int EVP_PKEY_keygen_init~(EVP_PKEY_CTX *ctx);

int EVP_DigestUpdate~(EVP_MD_CTX *ctx, const void *d, size_t cnt);
int EVP_EncodeBlock~(unsigned char *t, const unsigned char *f, int n);

ENGINE *ENGINE_new~(void);
int ENGINE_free~(ENGINE *e);
int ENGINE_set_id~(ENGINE *e, const char *id);
int ENGINE_set_name~(ENGINE *e, const char *name);
int ENGINE_set_init_function~(ENGINE *e, pfn init_f);
int ENGINE_set_finish_function~(ENGINE *e, pfn finish_f);
int ENGINE_set_destroy_function~(ENGINE *e, pfn destroy_f);
int ENGINE_set_ctrl_function~(ENGINE *e, pfn ctrl_f);
int ENGINE_set_RAND~(ENGINE *e, const RAND_METHOD *rand_meth);
int ENGINE_set_cmd_defns~(ENGINE *e, const ENGINE_CMD_DEFN *defns);

const EVP_MD *EVP_sha1~(void);
int SHA1_Init~(SHA_CTX *c);
int SHA1_Final~(unsigned char *md, SHA_CTX *c);

int X509_check_private_key(void *x, void *k);
void X509_free~(X509 *a);
const char *X509_get_default_cert_area~(void);
int SSL_use_certificate_file(void *ssl, const char *file, int type);
int X509_verify_cert(void *ctx);
int X509_load_cert_file(void *ctx, const char *file, int type);
int X509_STORE_add_cert(void *ctx, void *x);
const char* X509_get_default_cert_file~(void);
const char* X509_get_default_cert_file_env~(void);
int X509_load_cert_crl_file(void *ctx, const char *file, int type);
const char *X509_get_default_cert_dir~(void);
const char *X509_get_default_cert_dir_env~(void);
const char *X509_verify_cert_error_string(long n);
int X509_STORE_CTX_get_error~(X509_STORE_CTX *ctx);
int X509_STORE_CTX_get_error_depth~(X509_STORE_CTX *ctx);
X509 *X509_STORE_CTX_get_current_cert~(X509_STORE_CTX *ctx);
int X509_STORE_load_locations(void *store, const char *file, const char *dirs);

X509_NAME *X509_get_subject_name~(X509 *a);
char *X509_NAME_oneline~(X509_NAME *a, char *buf/p, int size);
X509_NAME *X509_get_issuer_name~(X509 *a);

X509 *SSL_get_peer_certificate(const SSL *ssl);
void *SSL_get_peer_cert_chain~(const SSL *s);

X509_LOOKUP_METHOD *X509_LOOKUP_hash_dir~(void);

enum_bm conf_mflags {
	CONF_MFLAGS_IGNORE_ERRORS       = 0x1,
	CONF_MFLAGS_IGNORE_RETURN_CODES = 0x2,
	CONF_MFLAGS_SILENT              = 0x4,
	CONF_MFLAGS_NO_DSO              = 0x8,
	CONF_MFLAGS_IGNORE_MISSING_FILE = 0x10,
	CONF_MFLAGS_DEFAULT_SECTION     = 0x20
};

CONF *NCONF_new~(CONF_METHOD *meth);
void NCONF_free!(CONF *conf);
CONF_METHOD *NCONF_default~(void);
int NCONF_load!(CONF *conf, const char *file, long *eline);
int CONF_modules_load!(const CONF *cnf, const char *appname, unsigned long flags=conf_mflags);
int CONF_module_add~(const char *name, pfn ifunc, pfn ffunc);

BUF_MEM *BUF_MEM_new~(void);
void BUF_MEM_free~(BUF_MEM *a);
size_t BUF_strlcpy~(char *dst/p, const char *src, size_t size);
size_t BUF_strlcat~(char *dst, const char *src, size_t siz);
char *BUF_strdup~(const char *str);
char *BUF_strndup~(const char *str, size_t siz);

_LHASH *lh_new~(void *h, void *c);
void lh_free~(_LHASH *lh);
void *lh_delete~(_LHASH *lh, const void *data);
void *lh_insert~(_LHASH *lh, void *data);
void *lh_retrieve~(_LHASH *lh, const void *data);
unsigned long lh_strhash~(const char *c);
unsigned long lh_num_items~(const _LHASH *lh);
void lh_doall!(_LHASH *lh, pfn func);
void lh_doall_arg~(_LHASH *lh, pfn fn, void *arg);

//long bn_mul_add_words(void *rp, void *ap, int num, long w);

enum obj_name_type {
	OBJ_NAME_TYPE_UNDEF       = 0x00,
	OBJ_NAME_TYPE_MD_METH     = 0x01,
	OBJ_NAME_TYPE_CIPHER_METH = 0x02,
	OBJ_NAME_TYPE_PKEY_METH   = 0x03,
	OBJ_NAME_TYPE_COMP_METH   = 0x04,
	OBJ_NAME_TYPE_NUM         = 0x05
};

int OBJ_NAME_add~(const char *name, int type=obj_name_type, const char *data/p);
int OBJ_NAME_remove~(const char *name, int type=obj_name_type);
const char *OBJ_nid2sn~(int n);
int OBJ_obj2nid~(const ASN1_OBJECT *o);
const char *OBJ_NAME_get~(const char *name, int type=obj_name_type);
const void *OBJ_bsearch_~(const void *key, const void *base, int num, int size, pfn cmp);
const void *OBJ_bsearch_ex_~(const void *key, const void *base, int num, int size, pfn cmp, int flags);

int ASN1_item_i2d~(ASN1_VALUE *val, unsigned char **out, const ASN1_ITEM *it);

_STACK *sk_new~(pfn cmp);
_STACK *sk_new_null~(void);
void sk_free~(_STACK *st);
int sk_insert~(_STACK *st, void *data, int where);
int sk_push~(_STACK *st, void *data);
void sk_pop_free!(_STACK *st, pfn func);
int sk_num~(const _STACK *st);
void sk_value~(const _STACK *st, int i);
void sk_sort~(_STACK *sk);
_STACK *sk_dup~(_STACK *st);

const char *RAND_file_name~(char *buf/p, size_t num);
int RAND_load_file~(const char *filename, long max_bytes);
int RAND_bytes!(unsigned char *buf, int num);
int RAND_pseudo_bytes!(unsigned char *buf, int num);
//void RAND_add~(const void *buf, int num, double entropy);
int RAND_status~(void);

void BN_free~(BIGNUM *a);
