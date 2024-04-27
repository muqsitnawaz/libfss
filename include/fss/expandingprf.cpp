
#include "expandingprf.hpp"

namespace fss {
    void ExpandingPRF::generate(u_char *key, size_t input_size, u_char *out) {
        // Run PRNG for the given input_size.
        size_t num_keys_required = input_size / 16;
        for (size_t i = 0; i < num_keys_required; i++) {
#ifndef AESNI
            AES_encrypt(key, out + (i * 16), &aes_keys_[i]);
#else
            aesni_encrypt(key, out + (i * 16), &aes_keys_[i]);
#endif
        }
        for (size_t i = 0; i < input_size; i++) {
            out[i] = out[i] ^ key[i % 16];
        }
    }
}