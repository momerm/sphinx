
from cpython.mem cimport PyMem_Malloc, PyMem_Realloc, PyMem_Free


cdef extern from "openssl/evp.h":

    # The CIPHER functions

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

    # The HMAC functions

    ctypedef struct HMAC_CTX:
        pass

    size_t hmac_ctx_size()
    void HMAC_CTX_init(HMAC_CTX *ctx);
    int HMAC_Init_ex(HMAC_CTX *ctx, const void *key, int key_len, const EVP_MD *md, ENGINE *impl)
    int HMAC_Update(HMAC_CTX *ctx, const unsigned char *data, int len)
    int HMAC_Final(HMAC_CTX *ctx, unsigned char *md, unsigned int *len)
    void HMAC_CTX_cleanup(HMAC_CTX *ctx)

    # The MD functions

    ctypedef struct EVP_MD_CTX:
        pass

    ctypedef struct EVP_MD:
        pass

    int EVP_MD_size(const EVP_MD *md)
    int EVP_MD_block_size(const EVP_MD *md)
    const EVP_MD *EVP_get_digestbyname(const char *name)

    void EVP_MD_CTX_init(EVP_MD_CTX *ctx)
    int EVP_MD_CTX_cleanup(EVP_MD_CTX *ctx)
    EVP_MD_CTX *EVP_MD_CTX_create()
    void EVP_MD_CTX_destroy(EVP_MD_CTX *ctx)

    int EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl)
    int EVP_DigestUpdate(EVP_MD_CTX *ctx, const void *d, size_t cnt)
    int EVP_DigestFinal_ex(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s);
    int EVP_Digest(const void *data, size_t count, unsigned char *md, unsigned int *size, const EVP_MD *type, ENGINE *impl)


cdef class crypto:

    cdef EVP_CIPHER_CTX* ctx
    cdef const EVP_CIPHER* cipher
    cdef unsigned char* out
    cdef unsigned out_len
    cdef const EVP_MD* md
    cdef EVP_MD_CTX* md_ctx

    def __cinit__(self):
        self.ctx = EVP_CIPHER_CTX_new()
        self.cipher = EVP_get_cipherbyname("AES-128-CTR")
        self.out = <unsigned char *> PyMem_Malloc(4096)
        self.out_len = 4096

        self.md = EVP_get_digestbyname("SHA256")
        self.md_ctx = EVP_MD_CTX_create()


    def __dalloc__(self):
        PyMem_Free(self.out)
        EVP_CIPHER_CTX_free(self.ctx)
        EVP_MD_CTX_destroy(self.md_ctx)


    cdef ensure(self, unsigned int out_len):
        if out_len > self.out_len:
            PyMem_Free(self.out)
            self.out = <unsigned char *> PyMem_Malloc(out_len)
            self.out_len = out_len


    cpdef aes_ctr_c(self, const unsigned char * key, msg, const unsigned char* iv):
        self.ensure(len(msg))
        cdef int i;

        EVP_CipherInit_ex(self.ctx, self.cipher, NULL, key, iv, 1)
        EVP_CipherUpdate(self.ctx, self.out, &i, msg, len(msg))

        py_out = self.out[:len(msg)]
        return py_out


    cpdef hash(self, msg):
        cdef unsigned int i;

        cdef const char * s = msg

        EVP_Digest(s, len(msg), self.out, &i, self.md, NULL)
        return self.out[:i]


    cpdef lioness_enc(self, k, key, message):
        self.ensure(len(message))
    
        xshort =  message[:k]
        xlong = message[k:]

        cdef int i;

        cdef unsigned char * out_short = self.out
        cdef unsigned int short_len = 16
        cdef unsigned char * out_long = self.out + 16
        cdef unsigned int long_len = len(message) - 16
        
        cdef unsigned char d[32] 
        cdef unsigned int s;


        # Round 1

        # k1 = self.hash(xlong+key+b'1')[:k]
        EVP_DigestInit_ex(self.md_ctx, self.md, NULL)
        EVP_DigestUpdate(self.md_ctx, <unsigned char *>xlong, len(xlong))
        EVP_DigestUpdate(self.md_ctx, <unsigned char *>key, len(key))
        EVP_DigestUpdate(self.md_ctx, '1', 1)
        EVP_DigestFinal_ex(self.md_ctx, d, &s)

        # xshort = self.aes_ctr_c(key, xshort, iv = d)
        EVP_CipherInit_ex(self.ctx, self.cipher, NULL, key, d, 1)
        EVP_CipherUpdate(self.ctx, out_short, &i, xshort, short_len)

        
        # Round 2

        # xlong = self.aes_ctr_c(key, xlong, iv = xshort)
        EVP_CipherInit_ex(self.ctx, self.cipher, NULL, key, out_short, 1)
        EVP_CipherUpdate(self.ctx, out_long, &i, xlong, long_len)


        # Round 3

        # k3 = self.hash(xlong+key+b'3')[:k]
        EVP_DigestInit_ex(self.md_ctx, self.md, NULL)
        EVP_DigestUpdate(self.md_ctx, out_long, len(xlong))
        EVP_DigestUpdate(self.md_ctx, <unsigned char *>key, len(key))
        EVP_DigestUpdate(self.md_ctx, '3', 1)
        EVP_DigestFinal_ex(self.md_ctx, d, &s)

        # xshort = self.aes_ctr_c(key, xshort, iv = d)
        EVP_CipherInit_ex(self.ctx, self.cipher, NULL, key, d, 1)
        EVP_CipherUpdate(self.ctx, out_short, &i, out_short, short_len)


        # Round 4

        # xlong = self.aes_ctr_c(key, xlong, xshort)        
        EVP_CipherInit_ex(self.ctx, self.cipher, NULL, key, out_short, 1)
        EVP_CipherUpdate(self.ctx, out_long, &i, out_long, long_len)

        r4 = self.out[:len(message)]
        return r4
