
#include "fsscontext.hpp"

namespace fss {
    FSSContext::FSSContext(uint64_t p, uint8_t scaling, bool to_generate_keys) {
        num_bits_ = fast_floor_log2(p) + 1;
        plain_modulus_ = SmallModulus(p);
        scaling_ = scaling;

        aes_keys_ = (AES_KEY *) malloc(sizeof(AES_KEY) * prf_expansion_factor_);

        if (to_generate_keys) {
            // Initialize keys for Matyas–Meyer–Oseas one-way compression function
            for (size_t i = 0; i < prf_expansion_factor_; i++) {
                u_char rand_bytes[16];
                if (!RAND_bytes(rand_bytes, 16)) {
                    throw std::runtime_error("Random bytes failed.");
                }
#ifndef AESNI
                AES_set_encrypt_key(rand_bytes, 128, &(aes_keys_[i]));
#else
                aesni_set_encrypt_key(rand_bytes, 128, &(f->aes_keys[i]));
#endif
            }
        }
    }
}