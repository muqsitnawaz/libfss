// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <cstdint>
#include <type_traits>
#include "smallmodulus.hpp"
#include "defines.hpp"
#include "uintarith.hpp"

namespace seal::util {
    inline uint64_t negate_uint_mod(uint64_t operand,
                                    const SmallModulus &modulus) {
#ifdef SEAL_DEBUG
        if (modulus.is_zero())
            {
                throw std::invalid_argument("modulus");
            }
            if (operand >= modulus.value())
            {
                throw std::out_of_range("operand");
            }
#endif
        std::int64_t non_zero = (operand != 0);
        return (modulus.value() - operand)
               & static_cast<uint64_t>(-non_zero);
    }

    inline std::uint64_t add_uint_uint_mod(std::uint64_t operand1,
                                           std::uint64_t operand2, const SmallModulus &modulus) {
#ifdef SEAL_DEBUG
        if (modulus.is_zero())
        {
            throw std::invalid_argument("modulus");
        }
        if (operand1 >= modulus.value())
        {
            throw std::out_of_range("operand1");
        }
        if (operand2 >= modulus.value())
        {
            throw std::out_of_range("operand2");
        }
#endif
        // Sum of operands modulo SmallModulus can never wrap around 2^64
        operand1 += operand2;
        return operand1 - (modulus.value() & static_cast<std::uint64_t>(
                -static_cast<std::int64_t>(operand1 >= modulus.value())));
    }

    inline std::uint64_t sub_uint_uint_mod(std::uint64_t operand1,
                                           std::uint64_t operand2, const SmallModulus &modulus) {
#ifdef SEAL_DEBUG
        if (modulus.is_zero())
        {
            throw std::invalid_argument("modulus");
        }

        if (operand1 >= modulus.value())
        {
            throw std::out_of_range("operand1");
        }
        if (operand2 >= modulus.value())
        {
            throw std::out_of_range("operand2");
        }
#endif
        unsigned long long temp;
        std::int64_t borrow = SEAL_SUB_BORROW_UINT64(operand1, operand2, 0, &temp);
        return static_cast<std::uint64_t>(temp) +
               (modulus.value() & static_cast<std::uint64_t>(-borrow));
    }

    template<typename T, typename = std::enable_if<is_uint64_v<T>>>
    inline uint64_t barrett_reduce_128(const T *input,
                                       const SmallModulus &modulus) {
#ifdef SEAL_DEBUG
        if (!input)
            {
                throw std::invalid_argument("input");
            }
            if (modulus.is_zero())
            {
                throw std::invalid_argument("modulus");
            }
#endif
        // Reduces input using base 2^64 Barrett reduction
        // input allocation size must be 128 bits

        unsigned long long tmp1, tmp2[2], tmp3, carry;
        const uint64_t *const_ratio = modulus.const_ratio().data();

        // Multiply input and const_ratio
        // Round 1
        multiply_uint64_hw64(input[0], const_ratio[0], &carry);

        multiply_uint64(input[0], const_ratio[1], tmp2);
        tmp3 = tmp2[1] + add_uint64(tmp2[0], carry, 0, &tmp1);

        // Round 2
        multiply_uint64(input[1], const_ratio[0], tmp2);
        carry = tmp2[1] + add_uint64(tmp1, tmp2[0], 0, &tmp1);

        // This is all we care about
        tmp1 = input[1] * const_ratio[1] + tmp3 + carry;

        // Barrett subtraction
        tmp3 = input[0] - tmp1 * modulus.value();

        // Claim: One more subtraction is enough
        return static_cast<uint64_t>(tmp3) -
               (modulus.value() & static_cast<uint64_t>(
                       -static_cast<std::int64_t>(tmp3 >= modulus.value())));
    }

    inline uint64_t multiply_uint_uint_mod(uint64_t operand1,
                                           uint64_t operand2, const SmallModulus &modulus) {
#ifdef SEAL_DEBUG
        if (modulus.is_zero())
            {
                throw std::invalid_argument("modulus");
            }
#endif
        unsigned long long z[2];
        multiply_uint64(operand1, operand2, z);
        return barrett_reduce_128(z, modulus);
    }
}

