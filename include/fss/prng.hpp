
#pragma once

#include <type_traits>
#include <random>

#include "seal/smallmodulus.hpp"

template <typename T>
concept Integral = std::is_integral_v<T>;

template <typename T>
concept UnsignedIntegral = Integral<T> and std::is_unsigned_v<T>;

namespace fss {
    template<UnsignedIntegral ValueType>
    using UniformDistType = std::uniform_int_distribution<ValueType>;

    struct PRNG {
        template<UnsignedIntegral ValueType>
        static auto get(ValueType bound) noexcept {
            static std::random_device device;
            static std::mt19937 engine(device());
            static std::unordered_map<ValueType, UniformDistType<ValueType>> dists;

            auto it = dists.find(bound);
            if (it == dists.end()) { it = dists.insert({bound, UniformDistType<ValueType>(0, bound - 1)}).first; }

            return it->second(engine);
        }

        static auto get(seal::SmallModulus bound) noexcept {
            return get<uint64_t>(bound.value());
        }
    };
}