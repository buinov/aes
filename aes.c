#include <stddef.h>
#include <stdint.h>
#include <limits.h>

#include "aes.h"
#include "aes_tables.h"

enum {
    word_size = sizeof(uint32_t),
    byte_bit_size = CHAR_BIT,
    word_bit_size = word_size * byte_bit_size
};

typedef union {
    uint32_t word;
    uint8_t byte[word_size];
} word_byte;

#ifndef AES_MIXCOLOMNS_MUL_TABLES
static const uint8_t aes_m = 0x1B;

static uint8_t xtime(uint8_t a) {
    return aes_m * (a >> 7) ^ (a << 1);
}
    #if 0
// c=a*b in GF(2)[x]/m(x) hex form m(x) is 0x11B
static uint8_t gf2_mul(uint8_t a, uint8_t b) {
    uint8_t c = 0;
    while(b) {
        // if(b & 1) c ^= a;
        c ^= a * (b & 1);
        a = xtime(a);
        b >>= 1;
    }
    return c;
}
    #endif // 0
#endif // !AES_MIXCOLOMNS_MUL_TABLES

static void add_round_key(aes_state_t* state, const aes_state_t* round_key) {
    for(size_t i = 0; i < aes_word_size; i++) {
        state->row[i].word ^= round_key->row[i].word;
    }
}

static void sub_bytes(aes_state_t* state) {
    for(size_t i = 0; i < aes_block_size; i++) {
        state->byte[i] = aes_sbox[state->byte[i]];
    }
}

static void shift_rows(aes_state_t* state) {
    for(size_t i = 1; i < aes_word_size; i++) {
        state->row[i].word = state->row[i].word << (word_bit_size - byte_bit_size * i) | state->row[i].word >> byte_bit_size * i;
    }
}

#ifdef AES_LOOKUP_TABLES
static void ssm_table(aes_state_t* state) {
    aes_state_t new_state = {0};
    for(size_t i = 0; i < aes_nb; i++) {
        word_byte temp = {.word = 0};
        for(size_t j = 0; j < aes_word_size; j++) {
            uint32_t inv_ssm_word = aes_ssm_table[state->matrix[j][(i + j) % aes_nb]];
            temp.word ^= ((inv_ssm_word << byte_bit_size *j) | (inv_ssm_word >> (word_bit_size - byte_bit_size * j)));
        }
        for(size_t j = 0; j < aes_word_size; j++) {
                new_state.matrix[j][i] ^= temp.byte[j];
        }
    }
    *state = new_state;
}
#else // !AES_LOOKUP_TABLES
static void mix_colomns(aes_state_t* state) {
    for(size_t i = 0; i < aes_nb; i++) {
        word_byte colomn = {.word = 0};
        for(size_t j = 0; j < aes_word_size; j++) {
    #ifdef AES_MIXCOLOMNS_MUL_TABLES
            uint8_t temp = state->matrix[j][i];
            colomn.byte[(j + 0) % aes_word_size] ^= aes_mulx2[temp];
            colomn.byte[(j + 1) % aes_word_size] ^= temp;
            colomn.byte[(j + 2) % aes_word_size] ^= temp;
            colomn.byte[(j + 3) % aes_word_size] ^= aes_mulx3[temp];
    #else // !AES_MIXCOLOMNS_MUL_TABLES
            uint8_t zero_xtime = state->matrix[j][i];
            uint8_t one_xtime = xtime(zero_xtime);
            colomn.byte[(j + 0) % aes_word_size] ^= one_xtime;
            colomn.byte[(j + 1) % aes_word_size] ^= zero_xtime;
            colomn.byte[(j + 2) % aes_word_size] ^= zero_xtime;
            colomn.byte[(j + 3) % aes_word_size] ^= one_xtime ^ zero_xtime;
    #endif // !AES_MIXCOLOMNS_MUL_TABLES
        }
        for(size_t j = 0; j < aes_word_size; j++) {
            state->matrix[j][i] = colomn.byte[j];
        }
    }
}
#endif // !AES_LOOKUP_TABLES

static void inv_sub_bytes(aes_state_t* state) {
    for(size_t i = 0; i < aes_block_size; i++) {
        state->byte[i] = aes_invsbox[state->byte[i]];
    }
}

static void inv_shift_rows(aes_state_t* state) {
    for(size_t i = 1; i < aes_word_size; i++) {
        state->row[i].word = state->row[i].word >> (word_bit_size - byte_bit_size * i) | state->row[i].word << byte_bit_size * i;
    }
}

#ifdef AES_LOOKUP_TABLES
static void inv_ssm_table(aes_state_t* state) {
    aes_state_t new_state = {0};
    for(size_t i = 0; i < aes_nb; i++) {
        word_byte temp = {.word = 0};
        for(size_t j = 0; j < aes_word_size; j++) {
            uint32_t ssm_word = aes_inv_ssm_table[state->matrix[j][(i - j) % aes_nb]];
            temp.word ^= (ssm_word << byte_bit_size *j) | (ssm_word >> (word_bit_size - byte_bit_size * j));
        }
        for(size_t j = 0; j < aes_word_size; j++) {
                new_state.matrix[j][i] ^= temp.byte[j];
        }
    }
    *state = new_state;
}
#endif // AES_LOOKUP_TABLES

static void inv_mix_colomns(aes_state_t* state) {
    for(size_t i = 0; i < aes_nb; i++) {
        word_byte colomn = {.word = 0};
        for(size_t j = 0; j < aes_word_size; j++) {
#ifdef AES_MIXCOLOMNS_MUL_TABLES
            uint8_t temp = state->matrix[j][i];
            colomn.byte[(j + 0) % aes_word_size] ^= aes_mulxe[temp];
            colomn.byte[(j + 1) % aes_word_size] ^= aes_mulx9[temp];
            colomn.byte[(j + 2) % aes_word_size] ^= aes_mulxd[temp];
            colomn.byte[(j + 3) % aes_word_size] ^= aes_mulxb[temp];
#else // !AES_MIXCOLOMNS_MUL_TABLES
            word_byte xtimes;
            xtimes.byte[0] = state->matrix[j][i];
            for(size_t k = 1; k < aes_word_size; k++) {
                xtimes.byte[k] = xtime(xtimes.byte[k - 1]);
            }
            uint8_t xnine = xtimes.byte[0] ^ xtimes.byte[3];
            colomn.byte[(j + 0) % aes_word_size] ^= xtimes.byte[1] ^ xtimes.byte[2] ^ xtimes.byte[3];
            colomn.byte[(j + 1) % aes_word_size] ^= xnine;
            colomn.byte[(j + 2) % aes_word_size] ^= xnine ^ xtimes.byte[2];
            colomn.byte[(j + 3) % aes_word_size] ^= xnine ^ xtimes.byte[1];
#endif // !AES_MIXCOLOMNS_MUL_TABLES
        }
        for(size_t j = 0; j < aes_word_size; j++) {
            state->matrix[j][i] = colomn.byte[j];
        }
    }
}

static void load(aes_state_t* state, const uint8_t* in) {
    for(size_t i = 0; i < aes_nb; i++) {
        for(size_t j = 0; j < aes_word_size; j++) {
            state->matrix[j][i] = in[i * aes_word_size + j];
        }
    }
}

static void store(aes_state_t* state, uint8_t* out) {
    for(size_t i = 0; i < aes_nb; i++) {
        for(size_t j = 0; j < aes_word_size; j++) {
            out[i * aes_word_size + j] = state->matrix[j][i];
        }
    }
}

void aes_encrypt(aes_ctx_t* ctx, const uint8_t* in, uint8_t* out) {
    const size_t nr_main = aes_nr_min + aes_nr_step * ctx->type;
    size_t i = 0;
    load(&ctx->state, in);

    add_round_key(&ctx->state, &ctx->expand_key.round_key[i++]);
    while(i < nr_main) {
#ifdef AES_LOOKUP_TABLES
        ssm_table(&ctx->state);
#else // !AES_LOOKUP_TABLES
        sub_bytes(&ctx->state);
        shift_rows(&ctx->state);
        mix_colomns(&ctx->state);
#endif // !AES_LOOKUP_TABLES
        add_round_key(&ctx->state, &ctx->expand_key.round_key[i++]);
    }
    sub_bytes(&ctx->state);
    shift_rows(&ctx->state);
    add_round_key(&ctx->state, &ctx->expand_key.round_key[i]);

    store(&ctx->state, out);
}

void aes_decrypt(aes_ctx_t* ctx, const uint8_t* in, uint8_t* out) {
    size_t i = aes_nr_min + aes_nr_step * ctx->type;
    load(&ctx->state, in);

    add_round_key(&ctx->state, &ctx->expand_key.round_key[i--]);
    while(i > 0) {
#ifdef AES_LOOKUP_TABLES
        inv_ssm_table(&ctx->state);
        add_round_key(&ctx->state, &ctx->expand_key.round_key[i--]);
#else // !AES_LOOKUP_TABLES
        inv_shift_rows(&ctx->state);
        inv_sub_bytes(&ctx->state);
        add_round_key(&ctx->state, &ctx->expand_key.round_key[i--]);
        inv_mix_colomns(&ctx->state);
#endif // !AES_LOOKUP_TABLES
    }
    inv_shift_rows(&ctx->state);
    inv_sub_bytes(&ctx->state);
    add_round_key(&ctx->state, &ctx->expand_key.round_key[i]);

    store(&ctx->state, out);
}

static uint32_t rot_word(uint32_t word) {
    return word << (word_bit_size - byte_bit_size) | word >> byte_bit_size;
}

static uint32_t sub_word(uint32_t word) {
    word_byte temp = {.word = word};
    for(size_t i = 0; i < word_size; i++) {
        temp.byte[i] = aes_sbox[temp.byte[i]];
    }
    return temp.word;
}

static uint32_t rcon(size_t i) {
#ifdef AES_LOOKUP_TABLES
    return aes_rcon[--i];
#else // !AES_LOOKUP_TABLES
    uint8_t rc = 1;
    while(--i) {
    #ifdef AES_MIXCOLOMNS_MUL_TABLES
        rc = aes_mulx2[rc];
    #else // !AES_MIXCOLOMNS_MUL_TABLES
        rc = xtime(rc);
    #endif // !AES_MIXCOLOMNS_MUL_TABLES
    }
    return rc;
#endif // !AES_LOOKUP_TABLES
}

void aes_init_key(aes_ctx_t* ctx, const uint8_t* key, aes_type_t type) {
    const size_t num_word_key = aes_nk_min + aes_nk_step * type;
    const size_t num_round = aes_nr_min + aes_nr_step * type + aes_nr_final;
    ctx->type = type;

    size_t i = 0;
    for(; i < num_word_key; i++) {
        for(size_t j = 0; j < aes_word_size; j++) {
            ctx->expand_key.round_key[i / aes_nb].matrix[j][i % aes_nb] = key[i * aes_word_size + j];
        }
    }

    for(; i < num_round * aes_nb; i++) {
        word_byte temp = {.word = 0};
        for(size_t j = 0; j < aes_word_size; j++) {
            temp.byte[j] ^= ctx->expand_key.round_key[(i - 1) / aes_nb].matrix[j][(i - 1) % aes_nb];
        }

        if(i % num_word_key == 0) {
            temp.word = sub_word(rot_word(temp.word)) ^ rcon(i / num_word_key);
        }
        if((i % num_word_key == aes_nk_min) &&
           (num_word_key > aes_nk_min + aes_nk_step)) {
            temp.word = sub_word(temp.word);
        }

        for(size_t j = 0; j < aes_word_size; j++) {
            ctx->expand_key.round_key[i / aes_nb].matrix[j][i % aes_nb] = ctx->expand_key.round_key[(i - num_word_key) / aes_nb].matrix[j][(i - num_word_key) % aes_nb] ^ temp.byte[j];
        }
    }
}

#ifdef AES_LOOKUP_TABLES
void aes_inv_mix_colomn_key(aes_expand_key_t *expand_key, aes_type_t type) {
    const size_t last_inv_mc_round_key = aes_nr_min + aes_nr_step * type;
    //skip first and last round key
    for(size_t i = 1; i < last_inv_mc_round_key; i++) {
        inv_mix_colomns(&expand_key->round_key[i]);
    }
}
#endif // AES_LOOKUP_TABLES
