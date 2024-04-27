// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "uintarith.hpp"
#include "common.hpp"
#include <algorithm>


namespace seal::util {
    void divide_uint192_uint64_inplace(uint64_t *numerator,
                                       uint64_t denominator, uint64_t *quotient) {
#ifdef SEAL_DEBUG
        if (!numerator)
        {
            throw std::invalid_argument("numerator");
        }
        if (denominator == 0)
        {
            throw std::invalid_argument("denominator");
        }
        if (!quotient)
        {
            throw std::invalid_argument("quotient");
        }
        if (numerator == quotient)
        {
            throw std::invalid_argument("quotient cannot point to same value as numerator");
        }
#endif
        // We expect 192-bit input
        size_t uint64_count = 3;

        // Clear quotient. Set it to zero.
        quotient[0] = 0;
        quotient[1] = 0;
        quotient[2] = 0;

        // Determine significant bits in numerator and denominator.
        int numerator_bits = get_significant_bit_count_uint(numerator, uint64_count);
        int denominator_bits = get_significant_bit_count(denominator);

        // If numerator has fewer bits than denominator, then done.
        if (numerator_bits < denominator_bits) {
            return;
        }

        // Only perform computation up to last non-zero uint64s.
        uint64_count = safe_cast<size_t>(
                divide_round_up(numerator_bits, bits_per_uint64));

        // Handle fast case.
        if (uint64_count == 1) {
            *quotient = *numerator / denominator;
            *numerator -= *quotient * denominator;
            return;
        }

        // Create temporary space to store mutable copy of denominator.
        std::vector<uint64_t> shifted_denominator(uint64_count, 0);
        shifted_denominator[0] = denominator;

        // Create temporary space to store difference calculation.
        std::vector<uint64_t> difference(uint64_count);

        // Shift denominator to bring MSB in alignment with MSB of numerator.
        int denominator_shift = numerator_bits - denominator_bits;

        left_shift_uint(shifted_denominator.data(), denominator_shift,
                        uint64_count, shifted_denominator.data());
        denominator_bits += denominator_shift;

        // Perform bit-wise division algorithm.
        int remaining_shifts = denominator_shift;
        while (numerator_bits == denominator_bits) {
            // NOTE: MSBs of numerator and denominator are aligned.

            // Even though MSB of numerator and denominator are aligned,
            // still possible numerator < shifted_denominator.
            if (sub_uint_uint(numerator, shifted_denominator.data(),
                              uint64_count, difference.data())) {
                // numerator < shifted_denominator and MSBs are aligned,
                // so current quotient bit is zero and next one is definitely one.
                if (remaining_shifts == 0) {
                    // No shifts remain and numerator < denominator so done.
                    break;
                }

                // Effectively shift numerator left by 1 by instead adding
                // numerator to difference (to prevent overflow in numerator).
                add_uint_uint(difference.data(), numerator, uint64_count, difference.data());

                // Adjust quotient and remaining shifts as a result of shifting numerator.
                left_shift_uint(quotient, 1, uint64_count, quotient);
                remaining_shifts--;
            }
            // Difference is the new numerator with denominator subtracted.

            // Update quotient to reflect subtraction.
            quotient[0] |= 1;

            // Determine amount to shift numerator to bring MSB in alignment with denominator.
            numerator_bits = get_significant_bit_count_uint(difference.data(), uint64_count);
            int numerator_shift = denominator_bits - numerator_bits;
            if (numerator_shift > remaining_shifts) {
                // Clip the maximum shift to determine only the integer
                // (as opposed to fractional) bits.
                numerator_shift = remaining_shifts;
            }

            // Shift and update numerator.
            if (numerator_bits > 0) {
                left_shift_uint(difference.data(), numerator_shift, uint64_count, numerator);
                numerator_bits += numerator_shift;
            } else {
                // Difference is zero so no need to shift, just set to zero.
                set_zero_uint(uint64_count, numerator);
            }

            // Adjust quotient and remaining shifts as a result of shifting numerator.
            left_shift_uint(quotient, numerator_shift, uint64_count, quotient);
            remaining_shifts -= numerator_shift;
        }

        // Correct numerator (which is also the remainder) for shifting of
        // denominator, unless it is just zero.
        if (numerator_bits > 0) {
            right_shift_uint(numerator, denominator_shift, uint64_count, numerator);
        }
    }
}

