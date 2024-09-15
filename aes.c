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
    for(size_t i = 0; i < aes_nb; i++) {
        state->colomn[i].word ^= round_key->colomn[i].word;
    }
}

static void sub_bytes(aes_state_t* state) {
    for(size_t i = 0; i < aes_block_size; i++) {
        state->byte[i] = aes_sbox[state->byte[i]];
    }
}

static void shift_rows(aes_state_t* state) {
    // shift row 1
    uint8_t temp = state->matrix[0][1];
    state->matrix[0][1] = state->matrix[1][1];
    state->matrix[1][1] = state->matrix[2][1];
    state->matrix[2][1] = state->matrix[3][1];
    state->matrix[3][1] = temp;

    // shift row 2
    temp = state->matrix[0][2];
    state->matrix[0][2] = state->matrix[2][2];
    state->matrix[2][2] = temp;
    temp = state->matrix[1][2];
    state->matrix[1][2] = state->matrix[3][2];
    state->matrix[3][2] = temp;

    //shift row 3
    temp = state->matrix[0][3];
    state->matrix[0][3] = state->matrix[3][3];
    state->matrix[3][3] = state->matrix[2][3];
    state->matrix[2][3] = state->matrix[1][3];
    state->matrix[1][3] = temp;
}

#ifdef AES_LOOKUP_TABLES
static void ssm_table(aes_state_t* state) {
    aes_state_t new_state = {0};
    for(size_t i = 0; i < aes_nb; i++) {
        for(size_t j = 0; j < aes_word_size; j++) {
            uint32_t temp = aes_ssm_table[state->matrix[(i + j) % aes_nb][j]];
            new_state.colomn[i].word ^= ((temp << byte_bit_size *j) | (temp >> (word_bit_size - byte_bit_size * j)));
        }
    }
    *state = new_state;
}
#else // !AES_LOOKUP_TABLES
static void mix_colomns(aes_state_t* state) {
    for(size_t i = 0; i < aes_nb; i++) {
        aes_colomn_t colomn = state->colomn[i];
        state->colomn[i].word = 0;
        for(size_t j = 0; j < aes_word_size; j++) {
    #ifdef AES_MIXCOLOMNS_MUL_TABLES
            uint8_t temp = colomn.byte[j];
            state->colomn[i].byte[(j + 0) % aes_word_size] ^= aes_mulx2[temp];
            state->colomn[i].byte[(j + 1) % aes_word_size] ^= temp;
            state->colomn[i].byte[(j + 2) % aes_word_size] ^= temp;
            state->colomn[i].byte[(j + 3) % aes_word_size] ^= aes_mulx3[temp];
    #else // !AES_MIXCOLOMNS_MUL_TABLES
            uint8_t zero_xtime = colomn.byte[j];
            uint8_t one_xtime = xtime(zero_xtime);
            state->colomn[i].byte[(j + 0) % aes_word_size] ^= one_xtime;
            state->colomn[i].byte[(j + 1) % aes_word_size] ^= zero_xtime;
            state->colomn[i].byte[(j + 2) % aes_word_size] ^= zero_xtime;
            state->colomn[i].byte[(j + 3) % aes_word_size] ^= one_xtime ^ zero_xtime;
    #endif // !AES_MIXCOLOMNS_MUL_TABLES
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
    // shift row 1
    uint8_t temp = state->matrix[0][1];
    state->matrix[0][1] = state->matrix[3][1];
    state->matrix[3][1] = state->matrix[2][1];
    state->matrix[2][1] = state->matrix[1][1];
    state->matrix[1][1] = temp;

    // shift row 2
    temp = state->matrix[0][2];
    state->matrix[0][2] = state->matrix[2][2];
    state->matrix[2][2] = temp;
    temp = state->matrix[1][2];
    state->matrix[1][2] = state->matrix[3][2];
    state->matrix[3][2] = temp;

    // shift row 3
    temp = state->matrix[0][3];
    state->matrix[0][3] = state->matrix[1][3];
    state->matrix[1][3] = state->matrix[2][3];
    state->matrix[2][3] = state->matrix[3][3];
    state->matrix[3][3] = temp;
}

#ifdef AES_LOOKUP_TABLES
static void inv_ssm_table(aes_state_t* state) {
    aes_state_t new_state = {0};
    for(size_t i = 0; i < aes_nb; i++) {
        for(size_t j = 0; j < aes_word_size; j++) {
            uint32_t temp = aes_inv_ssm_table[state->matrix[(i - j) % aes_nb][j]];
            new_state.colomn[i].word ^= ((temp << byte_bit_size *j) | (temp >> (word_bit_size - byte_bit_size * j)));
        }
    }
    *state = new_state;
}
#endif // AES_LOOKUP_TABLES

static void inv_mix_colomns(aes_state_t* state) {
    for(size_t i = 0; i < aes_nb; i++) {
        aes_colomn_t colomn = state->colomn[i];
        state->colomn[i].word = 0;
        for(size_t j = 0; j < aes_word_size; j++) {
#ifdef AES_MIXCOLOMNS_MUL_TABLES
            uint8_t temp = colomn.byte[j];
            state->colomn[i].byte[(j + 0) % aes_word_size] ^= aes_mulxe[temp];
            state->colomn[i].byte[(j + 1) % aes_word_size] ^= aes_mulx9[temp];
            state->colomn[i].byte[(j + 2) % aes_word_size] ^= aes_mulxd[temp];
            state->colomn[i].byte[(j + 3) % aes_word_size] ^= aes_mulxb[temp];
#else // !AES_MIXCOLOMNS_MUL_TABLES
            aes_colomn_t xtimes = {.byte[0] = colomn.byte[j]};
            for(size_t k = 1; k < aes_word_size; k++) {
                xtimes.byte[k] = xtime(xtimes.byte[k - 1]);
            }
            uint8_t xnine = xtimes.byte[0] ^ xtimes.byte[3];
            state->colomn[i].byte[(j + 0) % aes_word_size] ^= xtimes.byte[1] ^ xtimes.byte[2] ^ xtimes.byte[3];
            state->colomn[i].byte[(j + 1) % aes_word_size] ^= xnine;
            state->colomn[i].byte[(j + 2) % aes_word_size] ^= xnine ^ xtimes.byte[2];
            state->colomn[i].byte[(j + 3) % aes_word_size] ^= xnine ^ xtimes.byte[1];
#endif // !AES_MIXCOLOMNS_MUL_TABLES
        }
    }
}

static void load(aes_state_t* state, const uint8_t* in) {
    for(size_t i = 0; i < aes_block_size; i++) {
        state->byte[i] = in[i];
    }
}

static void store(aes_state_t* state, uint8_t* out) {
    for(size_t i = 0; i < aes_block_size; i++) {
        out[i] = state->byte[i];
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
            ctx->expand_key.round_key[i / aes_nb].colomn[i % aes_nb].byte[j] = key[i * aes_word_size + j];
        }
    }
    for(; i < num_round * aes_nb; i++) {
        aes_colomn_t temp = ctx->expand_key.round_key[(i - 1) / aes_nb].colomn[(i - 1) % aes_nb];

        if(i % num_word_key == 0) {
            temp.word = sub_word(rot_word(temp.word)) ^ rcon(i / num_word_key);
        }
        if((i % num_word_key == aes_nk_min) &&
           (num_word_key > aes_nk_min + aes_nk_step)) {
            temp.word = sub_word(temp.word);
        }
        ctx->expand_key.round_key[i / aes_nb].colomn[i % aes_nb].word = ctx->expand_key.round_key[(i - num_word_key) / aes_nb].colomn[(i - num_word_key) % aes_nb].word ^ temp.word;
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
