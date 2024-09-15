#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "aes.h"

// Test vectors from FIPS-197
const uint8_t aes_128_key_test[aes_128_key_size] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

const uint8_t aes_192_key_test[aes_192_key_size] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17};

const uint8_t aes_256_key_test[aes_256_key_size] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};

const uint8_t aes_input_test[aes_block_size] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};

const uint8_t aes_128_output_test[aes_block_size] = {
    0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
    0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a};

const uint8_t aes_192_output_test[aes_block_size] = {
    0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0,
    0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91};

const uint8_t aes_256_output_test[aes_block_size] = {
    0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf,
    0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89};

uint8_t data[aes_block_size];

aes_ctx_t aes_ctx;

int main()
{
    aes_ctx_t *aes_ctx_p = &aes_ctx;
    aes_init_key(aes_ctx_p, aes_128_key_test, aes_128_type);

    aes_encrypt(aes_ctx_p, aes_input_test, data);
    if(memcmp(data, aes_128_output_test, aes_block_size) == 0)
        printf("AES-128 encryption good\n");
    else
        printf("AES-128 encryption bad\n");

#ifdef AES_LOOKUP_TABLES
    aes_inv_mix_colomn_key(&aes_ctx_p->expand_key, aes_ctx_p->type);
#endif // AES_LOOKUP_TABLES
    aes_decrypt(aes_ctx_p, aes_128_output_test, data);
    if(memcmp(data, aes_input_test, aes_block_size) == 0)
        printf("AES-128 decryption good\n");
    else
        printf("AES-128 decryption bad\n");

    aes_init_key(aes_ctx_p, aes_192_key_test, aes_192_type);

    aes_encrypt(aes_ctx_p, aes_input_test, data);
    if(memcmp(data, aes_192_output_test, aes_block_size) == 0)
        printf("AES-192 encryption good\n");
    else
        printf("AES-192 encryption bad\n");

#ifdef AES_LOOKUP_TABLES
    aes_inv_mix_colomn_key(&aes_ctx_p->expand_key, aes_ctx_p->type);
#endif // AES_LOOKUP_TABLES
    aes_decrypt(aes_ctx_p, aes_192_output_test, data);
    if(memcmp(data, aes_input_test, aes_block_size) == 0)
        printf("AES-192 decryption good\n");
    else
        printf("AES-192 decryption bad\n");

    aes_init_key(aes_ctx_p, aes_256_key_test, aes_256_type);

    aes_encrypt(aes_ctx_p, aes_input_test, data);
    if(memcmp(data, aes_256_output_test, aes_block_size) == 0)
        printf("AES-256 encryption good\n");
    else
        printf("AES-256 encryption bad\n");

#ifdef AES_LOOKUP_TABLES
    aes_inv_mix_colomn_key(&aes_ctx_p->expand_key, aes_ctx_p->type);
#endif // AES_LOOKUP_TABLES
    aes_decrypt(aes_ctx_p, aes_256_output_test, data);
    if(memcmp(data, aes_input_test, aes_block_size) == 0)
        printf("AES-256 decryption good\n");
    else
        printf("AES-256 decryption bad\n");

    return 0;
}
