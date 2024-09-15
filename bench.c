#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include <unistd.h>

#include "aes.h"

// Test vectors from FIPS-197
const uint8_t aes_128_key[aes_128_key_size] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

const uint8_t aes_192_key[aes_192_key_size] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17};

const uint8_t aes_256_key[aes_256_key_size] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};

const uint8_t aes_input[aes_block_size] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};

const uint8_t aes_128_output[aes_block_size] = {
    0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
    0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a};

const uint8_t aes_192_output[aes_block_size] = {
    0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0,
    0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91};

const uint8_t aes_256_output[aes_block_size] = {
    0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf,
    0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89};

uint8_t data[aes_block_size];

aes_ctx_t aes_ctx;

const char help_msg[] =
    "Usage: bench -t [0/1/2] -m [e/d] -n [num]\n"
    "  -t    0 - AES-128(default), 1 - AES-192, 2 - AES-256\n"
    "  -m    e - encrypt(default)\\d - decrypt\n"
    "  -n    number blocks(default 1e+7)\n\n";

int main(int argc, char **argv){
    aes_ctx_t *aes_ctx_p = &aes_ctx;
    aes_type_t type = aes_128_type;
    bool mode = true;
    size_t number_blocks = 10000000;

    if(argc == 1)
        printf(help_msg);

    char *options = "t:m:n:";
    int opt;
    while((opt = getopt(argc, argv, options)) != -1) {
        switch(opt) {
            case 't': {
                int type_int = atoi(optarg);
                if(type_int == 0) type = aes_128_type;
                if(type_int == 1) type = aes_192_type;
                if(type_int == 2) type = aes_256_type;
                break;
            }
            case 'm':{
                bool encrypt, decrypt;
                encrypt = strcmp(optarg, "e") == 0;
                decrypt = strcmp(optarg, "d") == 0;
                if(encrypt || decrypt)
                    mode = encrypt;
                break;
            }
            case 'n': {
                int number_blocks_int = atoi(optarg);
                if(number_blocks_int > 0) number_blocks = (size_t)number_blocks_int;
                break;
            }
        }
    }

    printf("AES-%d ", (aes_128_key_size + type * aes_nk_step_byte) * CHAR_BIT);
    printf("%s ", mode ? "encrypt" : "decrypt");
    printf("%ld blocks\n", number_blocks);

    const uint8_t *aes_key;
    const uint8_t *aes_output;
    switch(type){
        case aes_128_type:
            aes_key = aes_128_key;
            aes_output = aes_128_output;
            break;
        case aes_192_type:
            aes_key = aes_192_key;
            aes_output = aes_192_output;
            break;
        case aes_256_type:
            aes_key = aes_256_key;
            aes_output = aes_256_output;
            break;
    }

    aes_init_key(aes_ctx_p, aes_key, type);
    #ifdef AES_LOOKUP_TABLES
    if(!mode)
        aes_inv_mix_colomn_key(&aes_ctx_p->expand_key, aes_ctx_p->type);
    #endif // AES_LOOKUP_TABLES

    printf("Start bench\n");

    if(mode) {
        while(number_blocks--)
            aes_encrypt(aes_ctx_p, aes_input, data);
    }
    else {
        while(number_blocks--)
            aes_decrypt(aes_ctx_p, aes_output, data);
    }

    bool check;
    if(mode)
        check = memcmp(aes_output, data, aes_block_size) == 0 ? true : false;
    else
        check = memcmp(aes_input, data, aes_block_size) == 0 ? true : false;

    if(check)
        printf("Finish good\n");
    else
        printf("Finish bad\n");

    return 0;
}
