
/* /usr/include/openssl/ssl.h (and friends) */

int SSL_library_init(void);
int SSL_CTX_set_cipher_list(void *ctx, const char *str);
int SSL_set_cipher_list(void *ssl, const char *str);
int SSL_accept(void *ssl);
int SSL_connect(void *ssl);
void *SSL_new(void *ctx);
void SSL_CTX_free(void *ctx);
void *SSL_CTX_new(void *method);
void SSL_CTX_set_verify(void *ctx, int mode, void *verify_cb);
void SSL_CTX_set_verify_depth(void *ctx, int depth);
int SSL_CTX_load_verify_locations(void *ctx, const char *CAfile, const char *CApath);
long SSL_CTX_ctrl(void *ctx, int cmd, long larg, void *parg);
int SSL_CTX_set_default_verify_paths(void *ctx);
void *SSL_SESSION_new(void);
void SSL_SESSION_free(void *session);
void OPENSSL_cleanse(void *ptr, size_t len);
void OPENSSL_config(const char *config_name);
void OPENSSL_no_config(void);
int SSL_version(void *s);
int SSL_CTX_check_private_key(void *ctx);
int SSL_check_private_key(void *ssl);
void CRYPTO_lock(int mode, int n, const char *file, int line);
int SSL_read(void *ssl, void *buf, int num);
int SSL_write(void *ssl, void *buf, int num);
int SSL_get_fd(void *ssl);
int SSL_get_rfd(void *ssl);
int SSL_get_wfd(void *ssl);
void CRYPTO_free(void *ptr);
void *CRYPTO_malloc(int num, const char *file, int line);
const char *ERR_func_error_string(long e);
int SSL_CTX_use_PrivateKey(void *ctx, void *pkey);
int SSL_use_PrivateKey_file(void *ssl, const char *file, int type);
int SSL_CTX_use_certificate(void *ctx, void *x);
int SSL_state(void *ssl);

void ERR_load_SSL_strings(void);
void ERR_load_crypto_strings(void);
void ERR_free_strings(void);
int SSL_get_error(void *ssl, int ret);

void *BIO_new(void *type);
int BIO_free(void *a);
long BIO_ctrl(void *bp, int cmd|bio_ctrl_cmd, long larg, char *parg/6b);
int BIO_read(void *b, void *buf, int len);
int BIO_gets(void *b, char *buf, int size);
int BIO_write(void *b, const void *buf, int len);
int BIO_puts(void *b, const char *buf);
int BIO_printf(void *bio, const char *format, void *args); 
unsigned long BIO_number_written(void *bio);
unsigned long BIO_number_read(void *bio);
void *BIO_find_type(void *b, int bio_type|bio_type);
int BIO_dump_indent (void *bp, const char *s, int len, int indent);
int BIO_dump_indent_fp (void *fp, const char *s, int len, int indent);
void *SSL_get_rbio(void *ssl);
void *SSL_get_wbio(void *ssl);
void *PEM_read_bio_PrivateKey(void *bp, void **x, void *cb, void *u);
void *PEM_read_bio_X509_AUX(void *bp, void **x, void *cb, void *u);

void *EVP_PKEY_new(void);

int X509_check_private_key(void *x, void *k);
void X509_free(void *a);
const char *X509_get_default_cert_area(void);
int SSL_use_certificate_file(void *ssl, const char *file, int type);
int X509_verify_cert(void *ctx);
int X509_load_cert_file(void *ctx, const char *file, int type);
int X509_STORE_add_cert(void *ctx, void *x);
const char* X509_get_default_cert_file(void);
const char* X509_get_default_cert_file_env(void);
int X509_load_cert_crl_file(void *ctx, const char *file, int type);
const char *X509_get_default_cert_dir(void);
const char *X509_get_default_cert_dir_env(void);
const char *X509_verify_cert_error_string(long n);
int X509_STORE_CTX_get_error(void *ctx);
int X509_STORE_CTX_get_error_depth(void *ctx);
void *X509_STORE_CTX_get_current_cert(void *ctx);
int X509_STORE_load_locations(void *store, const char *file, const char *dirs);
long ERR_get_error(void);

void *SSL_get_peer_certificate(void *ssl);

int NCONF_load(void *conf, const char *file, long *eline);

size_t BUF_strlcpy(void *dst, const char *src, size_t size);

void *lh_insert(void *lh, void *data);

//long bn_mul_add_words(void *rp, void *ap, int num, long w);
