
#pragma once

#include <cstdint>
#include <memory>
#include <exception>

#include <openssl/rand.h>
#include <openssl/aes.h>

#include "seal/smallmodulus.hpp"

#include <fss/common.hpp>

using namespace seal;

namespace fss {
    class FSSContext {
    public:
        /**
         * @returns A std::shared_ptr to FSSContext.
         */
        static auto Create(uint64_t plain_modulus, uint8_t frac_bits_count, bool to_generate_keys = true) {
            return std::shared_ptr<FSSContext>(new FSSContext(plain_modulus, frac_bits_count, to_generate_keys));
        }

        /**
         * Sets the AES_Key at given index.
         */
        inline void set_aes_key(size_t index, AES_KEY aes_key) const {
            if (index > prf_expansion_factor_ - 1) {
                throw std::invalid_argument("Index must be within [0, PRF_EXPANSION_FACTOR).");
            }
            aes_keys_[index] = aes_key;
        }

        [[nodiscard]] inline auto num_bits() const noexcept {
            return num_bits_;
        }

        [[nodiscard]] inline auto scaling() const noexcept {
            return scaling_;
        }

        [[nodiscard]] inline auto &plain_modulus() const noexcept {
            return plain_modulus_;
        }

        [[nodiscard]] inline auto prf_expansion_factor() const noexcept {
            return prf_expansion_factor_;
        }

        [[nodiscard]] inline auto &aes_key(size_t index) {
            if (index > prf_expansion_factor_ - 1) {
                throw std::invalid_argument("Index must be within [0, PRF_EXPANSION_FACTOR).");
            }
            return aes_keys_[index];
        }

        [[nodiscard]] inline const auto &aes_key(size_t index) const {
            if (index > prf_expansion_factor_ - 1) {
                throw std::invalid_argument("Index must be within [0, PRF_EXPANSION_FACTOR).");
            }
            return aes_keys_[index];
        }

        /*
         * Delete unnecessary members.
         */
        FSSContext() = delete;

    private:
        FSSContext(uint64_t p, uint8_t scaling, bool to_generate_keys);

        AES_KEY *aes_keys_;

        uint32_t num_bits_ = 0;

        uint8_t scaling_ = 0;

        SmallModulus plain_modulus_ = 0;

        const size_t prf_expansion_factor_ = 8;
    };
}