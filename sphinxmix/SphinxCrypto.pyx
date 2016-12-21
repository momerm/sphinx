
from cpython.mem cimport PyMem_Malloc, PyMem_Realloc, PyMem_Free


cdef extern from "openssl/evp.h":

    ctypedef struct ENGINE:
        pass

    ctypedef struct EVP_CIPHER:
        int nid
        int block_size
        int key_len
        int iv_len
        unsigned long flags

    ctypedef EVP_CIPHER* EVP_CIPHER_PT

    ctypedef struct EVP_CIPHER_CTX:
        const EVP_CIPHER *cipher
        int encrypt
        int buf_len
        int num
        int key_len
        unsigned long flags
        int final_used
        int block_mask

    void init_ciphers()
    void cleanup_ciphers()

    void EVP_CIPHER_CTX_init(EVP_CIPHER_CTX* a)
    int EVP_CIPHER_CTX_cleanup(EVP_CIPHER_CTX* a)
    EVP_CIPHER_CTX* EVP_CIPHER_CTX_new()
    void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX* a)
    int EVP_CIPHER_CTX_set_key_length(EVP_CIPHER_CTX *x, int keylen)
    int EVP_CIPHER_CTX_set_padding(EVP_CIPHER_CTX *c, int pad)
    int EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr)
    int EVP_CIPHER_CTX_rand_key(EVP_CIPHER_CTX *ctx, unsigned char *key)

    const EVP_CIPHER *EVP_get_cipherbyname(const char *name)
    int  EVP_CipherInit_ex(EVP_CIPHER_CTX *ctx,const EVP_CIPHER *cipher, ENGINE *impl,const unsigned char *key,const unsigned char *iv, int enc)
    int  EVP_CipherUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl, const unsigned char *inm, int inl)
    int  EVP_CipherFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl)

    ctypedef struct HMAC_CTX:
        pass

    ctypedef struct EVP_MD:
        pass

    int EVP_MD_size(const EVP_MD *md)
    int EVP_MD_block_size(const EVP_MD *md)
    const EVP_MD *EVP_get_digestbyname(const char *name)

    size_t hmac_ctx_size()
    void HMAC_CTX_init(HMAC_CTX *ctx);
    int HMAC_Init_ex(HMAC_CTX *ctx, const void *key, int key_len, const EVP_MD *md, ENGINE *impl)
    int HMAC_Update(HMAC_CTX *ctx, const unsigned char *data, int len)
    int HMAC_Final(HMAC_CTX *ctx, unsigned char *md, unsigned int *len)
    void HMAC_CTX_cleanup(HMAC_CTX *ctx)

    ctypedef struct EVP_MD_CTX:
        pass

    void EVP_MD_CTX_init(EVP_MD_CTX *ctx)
    int EVP_MD_CTX_cleanup(EVP_MD_CTX *ctx)
    EVP_MD_CTX *EVP_MD_CTX_create()
    void EVP_MD_CTX_destroy(EVP_MD_CTX *ctx)

    int EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl)
    int EVP_DigestUpdate(EVP_MD_CTX *ctx, const void *d, size_t cnt)
    int EVP_DigestFinal_ex(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s);
    int EVP_Digest(const void *data, size_t count, unsigned char *md, unsigned int *size, const EVP_MD *type, ENGINE *impl)

def hello():
    return "Hello"


def aes_ctr_c(key, msg, iv):
    cdef EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new()
    cdef const EVP_CIPHER* cipher = EVP_get_cipherbyname("AES-128-CTR")

    cdef unsigned char * out = <unsigned char *> PyMem_Malloc(len(msg))
    cdef int i;

    EVP_CipherInit_ex(ctx, cipher, NULL, key, iv, 1)
    EVP_CipherUpdate(ctx, out, &i, msg, len(msg))

    py_out = out[:len(msg)]

    PyMem_Free(out)
    EVP_CIPHER_CTX_free(ctx)

    return py_out

"""

/* 

    EVP Ciphers 

*/

typedef struct evp_cipher_st
{
    int nid;
    int block_size;
    int key_len; /* Default value for variable length ciphers */
    int iv_len;
    unsigned long flags; /* Various flags */
    ...;
} EVP_CIPHER;

typedef struct evp_cipher_ctx_st
{
    const EVP_CIPHER *cipher;
    int encrypt; /* encrypt or decrypt */
    int buf_len; /* number we have left */
    int num; /* used by cfb/ofb/ctr mode */
    int key_len; /* May change for variable length cipher */
    unsigned long flags; /* Various flags */
    int final_used;
    int block_mask;
    ...;
} EVP_CIPHER_CTX;

const EVP_CIPHER * EVP_aes_128_gcm(void);
const EVP_CIPHER * EVP_aes_192_gcm(void);
const EVP_CIPHER * EVP_aes_256_gcm(void);

typedef ... ENGINE; // Ignore details of the engine.

// Cipher context operations

void EVP_CIPHER_CTX_init(EVP_CIPHER_CTX *a);
int EVP_CIPHER_CTX_cleanup(EVP_CIPHER_CTX *a);
EVP_CIPHER_CTX *EVP_CIPHER_CTX_new(void);
void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *a);
int EVP_CIPHER_CTX_set_key_length(EVP_CIPHER_CTX *x, int keylen);
int EVP_CIPHER_CTX_set_padding(EVP_CIPHER_CTX *c, int pad);
int EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr);
int EVP_CIPHER_CTX_rand_key(EVP_CIPHER_CTX *ctx, unsigned char *key);

// Cipher operations

const EVP_CIPHER *EVP_get_cipherbyname(const char *name);

int  EVP_CipherInit_ex(EVP_CIPHER_CTX *ctx,const EVP_CIPHER *cipher, ENGINE *impl,
const unsigned char *key,const unsigned char *iv, int enc);
int  EVP_CipherUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
int *outl, const unsigned char *in, int inl);
int  EVP_CipherFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl);

// The control codes for ciphers

#define EVP_CTRL_INIT ...
#define EVP_CTRL_SET_KEY_LENGTH ...
#define EVP_CTRL_GET_RC2_KEY_BITS ...
#define EVP_CTRL_SET_RC2_KEY_BITS ...
#define EVP_CTRL_GET_RC5_ROUNDS ...
#define EVP_CTRL_SET_RC5_ROUNDS ...
#define EVP_CTRL_RAND_KEY ...
#define EVP_CTRL_PBE_PRF_NID  ...
#define EVP_CTRL_COPY ...
#define EVP_CTRL_GCM_SET_IVLEN  ...
#define EVP_CTRL_GCM_GET_TAG  ...
#define EVP_CTRL_GCM_SET_TAG  ...
#define EVP_CTRL_GCM_SET_IV_FIXED ...
#define EVP_CTRL_GCM_IV_GEN ...
#define EVP_CTRL_CCM_SET_IVLEN  ...
#define EVP_CTRL_CCM_GET_TAG  ...
#define EVP_CTRL_CCM_SET_TAG  ...
#define EVP_CTRL_CCM_SET_L  ...
#define EVP_CTRL_CCM_SET_MSGLEN ...
#define EVP_CTRL_AEAD_TLS1_AAD  ...
#define EVP_CTRL_AEAD_SET_MAC_KEY ...
#define EVP_CTRL_GCM_SET_IV_INV ...

 int EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
                 ENGINE *impl, unsigned char *key, unsigned char *iv);
 int EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
                 int *outl, unsigned char *in, int inl);
 int EVP_EncryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out,
                 int *outl);

 int EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
                 ENGINE *impl, unsigned char *key, unsigned char *iv);
 int EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
                 int *outl, unsigned char *in, int inl);
 int EVP_DecryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *outm,
                 int *outl);

void init_ciphers();
void cleanup_ciphers();

// The HMAC interface


typedef struct { ...; } HMAC_CTX;
typedef ... EVP_MD;

size_t hmac_ctx_size();

int EVP_MD_size(const EVP_MD *md);
int EVP_MD_block_size(const EVP_MD *md);
const EVP_MD *EVP_get_digestbyname(const char *name);


 void HMAC_CTX_init(HMAC_CTX *ctx);

 int HMAC_Init_ex(HMAC_CTX *ctx, const void *key, int key_len,
                                     const EVP_MD *md, ENGINE *impl);
 int HMAC_Update(HMAC_CTX *ctx, const unsigned char *data, int len);
 int HMAC_Final(HMAC_CTX *ctx, unsigned char *md, unsigned int *len);

 void HMAC_CTX_cleanup(HMAC_CTX *ctx);


"""