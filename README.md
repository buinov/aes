# AES
AES tiny configurable implementation

This implementation has an optional ability to use only multiplication by x in GF(2^8), use precomputed multiplication tables and lookup tables for the total transformation of SubBytes, ShiftRows and MixColomns.
By default, the method of multiplication by x in GF(2^8) is used.
To use multiplication tables, you need define AES_MIXCOLOMNS_MUL_TABLES.
To use lookup tables, you need define AES_LOOKUP_TABLES.

If decryption is required when using lookup tables, then after expanding the key with the aes_init_key function, you need apply the aes_inv_mix_colomn_key function to the expanded key.

The examples contain two programs: test to check the correctness of the implementation with test vectors from FIPS-197, and bench to evaluate the performance of the implementation.
