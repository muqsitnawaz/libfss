
#pragma once

#include <fss/fsscontext.hpp>

namespace fss {
    class ExpandingPRF {
    public:
        /**
         * Constructs an ExpandingPRF instance with the given FSSContext.
         *
         * @param fss_context The given FSSContext.
         */
        explicit ExpandingPRF(const std::shared_ptr<FSSContext> &fss_context) {
            // Verify parameters.
            if (!fss_context) {
                throw std::invalid_argument("Invalid FSSContext.");
            }

            // Copy over AESKeys from FSSContext.
            auto expansion_factor = fss_context->prf_expansion_factor();
            aes_keys_ = (AES_KEY *) malloc(sizeof(AES_KEY) * expansion_factor);
            for (size_t i = 0; i < expansion_factor; ++i) {
                aes_keys_[i] = fss_context->aes_key(i);
            }
        }

        /**
         * Implements an expanding pseudorandom function.
         *
         * @param[in] input_size The size of input.
         * @param[in] key The pointer to PRF key.
         * @param[out] out The pointer to output.
         */
        void generate(u_char *key, size_t input_size, u_char *out);

    private:
        AES_KEY *aes_keys_{nullptr};
    };
}