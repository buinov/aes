#ifndef AES_H
#define AES_H

#include <stdint.h>

//#define AES_MIXCOLOMNS_MUL_TABLES
//#define AES_LOOKUP_TABLES

typedef enum {
    aes_128_type = 0,
    aes_192_type = 1,
    aes_256_type = 2
} aes_type_t;

enum {
    aes_word_size = sizeof(uint32_t),

    aes_nb = aes_word_size,
    aes_block_size = aes_word_size * aes_nb,

    aes_nk_min = 4,
    aes_nk_step = 2,
    aes_nk_step_byte = aes_nk_step * aes_word_size,

    aes_nr_min = 10,
    aes_nr_step = 2,
    aes_nr_final = 1,
    aes_nr_max = aes_nr_min + aes_nr_step * aes_256_type + aes_nr_final
};

enum {
    aes_128_key_size = 16,
    aes_192_key_size = aes_128_key_size + aes_nk_step_byte,
    aes_256_key_size = aes_192_key_size + aes_nk_step_byte
};

typedef union {
    uint32_t word;
    uint8_t byte[aes_nb];
} aes_row_t;

typedef union {
    uint8_t byte[aes_block_size];
    aes_row_t row[aes_word_size];
    uint8_t matrix[aes_word_size][aes_nb];
} aes_state_t;

typedef struct {
    aes_state_t round_key[aes_nr_max];
} aes_expand_key_t;

typedef struct{
    aes_state_t state;
    aes_expand_key_t expand_key;
    aes_type_t type;
} aes_ctx_t;

void aes_init_key(aes_ctx_t* ctx, const uint8_t* key, aes_type_t type);

#ifdef AES_LOOKUP_TABLES
void aes_inv_mix_colomn_key(aes_expand_key_t *expand_key, aes_type_t type);
#endif // AES_LOOKUP_TABLES

void aes_encrypt(aes_ctx_t* ctx, const uint8_t* in, uint8_t* out);

void aes_decrypt(aes_ctx_t* ctx, const uint8_t* in, uint8_t* out);

#endif // !AES_H
