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

//void digest_message(const unsigned char *message, size_t message_len, unsigned char *digest);

#ifdef __cplusplus
}
#endif
#endif

