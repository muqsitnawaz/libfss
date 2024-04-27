
#pragma once

#include <iostream>
#include <vector>
#include <algorithm>
#include <cstring>

#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <fss/openssl-aes.h>

namespace fss {
    /**
     * @returns The bit at desired position from the given input.
     *
     * @param n The number to extract bit from.
     * @param pos The position of the desired bit.
     */
    inline uint64_t get_bit(uint64_t n, uint64_t pos) noexcept {
        return (n & (((uint64_t) 1) << (64 - pos))) >> (64 - pos);
    }

    /**
     * @returns The 128-bit unsigned number corresponding to the given byte array.
     *
     * @param arr The given array of bytes.
     */
    inline uint64_t byte_array_to_integer(const u_char *arr) noexcept {
        uint64_t i = ((uint64_t) arr[7] << 56u) | ((uint64_t) arr[6] << 48u) |
                     ((uint64_t) arr[5] << 40u) | ((uint64_t) arr[4] << 32u) |
                     ((uint64_t) arr[3] << 24u) | ((uint64_t) arr[2] << 16u) |
                     ((uint64_t) arr[1] << 8u) | ((uint64_t) arr[0]);
        return i;
    }

    /**
     * @returns The closest power of 2 greater than or equal to the given number.
     */
    inline uint64_t fast_floor_log2(uint64_t n) {
        uint64_t count = 0;

        if (n && !(n & (n - 1))) {
            while (n != 1) {
                n >>= 1u;
                count += 1;
            }
            return count;
        }

        while (n != 0) {
            n >>= 1u;
            count += 1;
        }

        return count;
    }
}