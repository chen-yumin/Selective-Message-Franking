#ifndef _SYMMETRIC
#define _SYMMETRIC

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#define CTX_LEN 32

#ifdef __cplusplus
extern "C" {
#endif

void printHex(uint8_t* data, int len);
void handleErrors(void);

int prg(uint8_t* seed, uint8_t* output, int output_len);

//expects 32 byte hmac key
int hmac_it(uint8_t* key, const unsigned char *msg, size_t mlen, unsigned char *mac_res);

int verify_hmac(uint8_t* key, const unsigned char *msg, size_t mlen, const unsigned char *val);

/**
 * SHA256 迭代扩展输出
 * @param in 原始输入
 * @param in_len 输入长度
 * @param out 输出缓冲区
 * @param out_len 需要输出总字节数
 * @return 成功1，失败0
 */

int sha256_expand(const uint8_t *in, size_t in_len, uint8_t *out, size_t out_len);

#ifdef __cplusplus
}
#endif

#endif

