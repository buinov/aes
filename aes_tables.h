#ifndef AES_TABLES_H
#define AES_TABLES_H

#include <stdint.h>

enum {
    aes_byte_value_num = 256,
    aes_mul_size = aes_byte_value_num,

    aes_sbox_size = aes_byte_value_num,
    aes_invsbox_size = aes_sbox_size,

    aes_rcon_size = 10
};

extern const uint8_t aes_sbox[];
extern const uint8_t aes_invsbox[];

#ifdef AES_LOOKUP_TABLES
extern const uint8_t aes_rcon[];
extern const uint32_t aes_ssm_table[];
extern const uint32_t aes_inv_ssm_table[];
#endif // AES_LOOKUP_TABLES

#ifdef AES_MIXCOLOMNS_MUL_TABLES
extern const uint8_t aes_mulx2[];
extern const uint8_t aes_mulx3[];
extern const uint8_t aes_mulx9[];
extern const uint8_t aes_mulxb[];
extern const uint8_t aes_mulxd[];
extern const uint8_t aes_mulxe[];
#endif // AES_MIXCOLOMNS_MUL_TABLES

#endif // !AES_TABLES_H
