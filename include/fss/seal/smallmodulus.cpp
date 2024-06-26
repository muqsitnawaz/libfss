// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "smallmodulus.hpp"
#include "uintarith.hpp"
#include "common.hpp"
#include <stdexcept>

using namespace seal::util;

namespace seal {
    void SmallModulus::save(std::ostream &stream) const {
        auto old_except_mask = stream.exceptions();
        try {
            // Throw exceptions on std::ios_base::badbit and std::ios_base::failbit
            stream.exceptions(std::ios_base::badbit | std::ios_base::failbit);

            stream.write(reinterpret_cast<const char *>(&value_), sizeof(uint64_t));
        }
        catch (const std::exception &) {
            stream.exceptions(old_except_mask);
            throw;
        }

        stream.exceptions(old_except_mask);
    }

    void SmallModulus::load(std::istream &stream) {
        auto old_except_mask = stream.exceptions();
        try {
            // Throw exceptions on std::ios_base::badbit and std::ios_base::failbit
            stream.exceptions(std::ios_base::badbit | std::ios_base::failbit);

            uint64_t value;
            stream.read(reinterpret_cast<char *>(&value), sizeof(uint64_t));
            set_value(value);
        }
        catch (const std::exception &) {
            stream.exceptions(old_except_mask);
            throw;
        }

        stream.exceptions(old_except_mask);
    }

    void SmallModulus::set_value(uint64_t value) {
        if (value == 0) {
            // Zero settings
            bit_count_ = 0;
            uint64_count_ = 1;
            value_ = 0;
            const_ratio_ = {{0, 0, 0}};
        } else if ((value >> 62 != 0) || (value == uint64_t(0x4000000000000000)) ||
                   (value == 1)) {
            throw std::invalid_argument("value can be at most 62 bits and cannot be 1");
        } else {
            // All normal, compute const_ratio and set everything
            value_ = value;
            bit_count_ = get_significant_bit_count(value_);

            // Compute Barrett ratios for 64-bit words (barrett_reduce_128)
            uint64_t numerator[3]{0, 0, 1};
            uint64_t quotient[3]{0, 0, 0};

            // Use a special method to avoid using memory pool
            divide_uint192_uint64_inplace(numerator, value_, quotient);

            const_ratio_[0] = quotient[0];
            const_ratio_[1] = quotient[1];

            // We store also the remainder
            const_ratio_[2] = numerator[0];

            uint64_count_ = 1;
        }
    }
}
