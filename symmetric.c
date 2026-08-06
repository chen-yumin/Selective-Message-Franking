#include "symmetric.h"


void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

//print out the data as a hex string
void printHex(uint8_t* data, int len)
{
    for(int i = 0; i < len; i++)
    {
        printf("%x", data[i]);
    }
    printf("\n");
}


//initialize AES in CTR mode with IV 0 using seed as key, encrypt all zeros
int prg(uint8_t* seed, uint8_t* output, int output_len)
{
    uint8_t *zeros = (uint8_t*) malloc(output_len);
    memset(zeros, 0, output_len);

    int len = 0;
    int final_len = 0;
    EVP_CIPHER_CTX *seed_ctx;

    //create ctx for PRG
    if(!(seed_ctx = EVP_CIPHER_CTX_new()))
        handleErrors();


    if(1 != EVP_EncryptInit_ex(seed_ctx, EVP_aes_128_ctr(), NULL, seed, NULL))
        handleErrors();

    if(1 != EVP_EncryptUpdate(seed_ctx, output, &len, zeros, output_len))
        handleErrors();

    if(1 != EVP_EncryptFinal_ex(seed_ctx, output+len, &final_len))
        handleErrors();

    len += final_len;

    //These two messages should never be printed
    if(len > output_len)
    {
        printf("longer output than expected!\n");
        return 0;
    }
    else if(len < output_len)
    {
        printf("shorter output than expected!\n");
        return 0;
    }

    free(zeros);
    EVP_CIPHER_CTX_free(seed_ctx);

    return 1;
}

int hmac_it(uint8_t* key, const unsigned char *msg, size_t mlen, unsigned char *macRes)
{

    //set up EVP_PKEY for 256 bit (32 byte) hmac key
    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_HMAC, NULL, key, 32);
    if(!pkey)
    {
        goto err;
    }

    /* Returned to caller */
    int result = 0;
    EVP_MD_CTX* ctx = NULL;
    size_t req = 0;
    int rc;

    if(!msg || !mlen || !macRes || !pkey)
        return 0;

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        printf("EVP_MD_CTX_create failed, error 0x%lx\n", ERR_get_error());
        goto err;
    }

    rc = EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, pkey);
    if (rc != 1) {
        printf("EVP_DigestSignInit failed, error 0x%lx\n", ERR_get_error());
        goto err;
    }

    rc = EVP_DigestSignUpdate(ctx, msg, mlen);
    if (rc != 1) {
        printf("EVP_DigestSignUpdate failed, error 0x%lx\n", ERR_get_error());
        goto err;
    }

    rc = EVP_DigestSignFinal(ctx, NULL, &req);
    if (rc != 1) {
        printf("EVP_DigestSignFinal failed (1), error 0x%lx\n", ERR_get_error());
        goto err;
    }

    size_t macLen = req;
    rc = EVP_DigestSignFinal(ctx, macRes, &macLen);
    if (rc != 1) {
        printf("EVP_DigestSignFinal failed (3), return code %d, error 0x%lx\n", rc, ERR_get_error());
        goto err;
    }

    if(macLen != 32)
    {
        printf("MAC wrong length!\n");
        goto err;
    }

    result = 1;


 err:
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return result;
}

int verify_hmac(uint8_t* key, const unsigned char *msg, size_t mlen, const unsigned char *tag)
{
    size_t tagLen = 32;

    //set up EVP_PKEY for 256 bit (32 byte) hmac key
    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_HMAC, NULL, key, 32);
    if(!pkey)
    {
        goto err;
    }

    /* Returned to caller */
    int result = 0;
    EVP_MD_CTX* ctx = NULL;
    unsigned char buff[EVP_MAX_MD_SIZE];
    size_t size;
    int rc;

    if(!msg || !mlen || !tag || !pkey)
        return 0;

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        printf("EVP_MD_CTX_create failed, error 0x%lx\n", ERR_get_error());
        goto err;
    }

    rc = EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, pkey);
    if (rc != 1) {
        printf("EVP_DigestSignInit failed, error 0x%lx\n", ERR_get_error());
        goto err;
    }

    rc = EVP_DigestSignUpdate(ctx, msg, mlen);
    if (rc != 1) {
        printf("EVP_DigestSignUpdate failed, error 0x%lx\n", ERR_get_error());
        goto err;
    }

    size = sizeof(buff);
    rc = EVP_DigestSignFinal(ctx, buff, &size);
    if (rc != 1) {
        printf("EVP_DigestSignFinal failed, error 0x%lx\n", ERR_get_error());
        goto err;
    }

    result = (tagLen == size) && (CRYPTO_memcmp(tag, buff, size) == 0);
 err:
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return result;
}

// SHAKE256 XOF 可扩展输出实现
int shake256_xof(const uint8_t *msg, size_t mlen, uint8_t *out, size_t out_len)
{
    if (!msg || !out || out_len == 0)
    {
        fprintf(stderr, "shake256_xof null param\n");
        return 0;
    }
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) handleErrors();

    if (EVP_DigestInit_ex(ctx, EVP_shake256(), NULL) != 1)
        handleErrors();
    if (EVP_DigestUpdate(ctx, msg, mlen) != 1)
        handleErrors();

    // 一次性读取目标长度，不再循环
    unsigned int req = (unsigned int)out_len;
    if (EVP_DigestFinalXOF(ctx, out, req) != 1)
        handleErrors();

    EVP_MD_CTX_free(ctx);
    return 1;
}

// SHA256 迭代扩展输出，替代shake256_xof
int sha256_expand(const uint8_t *in, size_t in_len, uint8_t *out, size_t out_len)
{
    if (!in || !out || out_len == 0)
    {
        fprintf(stderr, "sha256_expand null input\n");
        return 0;
    }
    uint8_t tmp_in[1024];
    memcpy(tmp_in, in, in_len);
    size_t pos = 0;
    uint8_t counter = 0;
    while (pos < out_len)
    {
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        if (!ctx) handleErrors();
        EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
        // 输入 = 原始数据 || counter
        EVP_DigestUpdate(ctx, tmp_in, in_len);
        EVP_DigestUpdate(ctx, &counter, 1);
        uint8_t hash[32];
        unsigned int hash_len;
        EVP_DigestFinal_ex(ctx, hash, &hash_len);
        EVP_MD_CTX_free(ctx);

        size_t copy = (out_len - pos) > 32 ? 32 : (out_len - pos);
        memcpy(out + pos, hash, copy);
        pos += copy;
        counter++;
    }
    return 1;
}



