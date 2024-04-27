
#include "fssevaluator.hpp"

namespace fss {
    uint64_t FSSEvaluator::dpf(const DPFKey &k, uint64_t x) {
        // start at the correct LSB
        int xi;
        u_char s[16];
        u_char t;

        u_char sArray[32];
        u_char temp[2];
        u_char out[48];
        u_char tau[48];
        memcpy(s, k.s, 16);
        t = server_id_;
        for (uint32_t i = 0; i < num_bits_; i++) {
            prf_->generate(s, 48, out);
            memcpy(sArray, out, 32);
            temp[0] = out[32] % 2;
            temp[1] = out[33] % 2;
            if (t == 0) {
                for (uint32_t j = 0; j < 16; j++) {
                    tau[j] = sArray[j];
                }
                for (uint32_t j = 0; j < 16; j++) {
                    tau[j + 16] = sArray[j + 16];
                }
                tau[32] = temp[0];
                tau[33] = temp[1];
            } else {
                for (uint32_t j = 0; j < 16; j++) {
                    tau[j] = sArray[j] ^ k.cw[i].cs[j];
                }
                for (uint32_t j = 0; j < 16; j++) {
                    tau[j + 16] = sArray[j + 16] ^ k.cw[i].cs[j];
                }
                tau[32] = temp[0] ^ k.cw[i].ct[0];
                tau[33] = temp[1] ^ k.cw[i].ct[1];
            }
            xi = get_bit(x, (64 - num_bits_ + i + 1));
            if (xi == 0) {
                memcpy(s, tau, 16);
                t = tau[32];
            } else {
                memcpy(s, tau + 16, 16);
                t = tau[33];
            }
        }
        uint64_t ans;

        ans = (uint64_t) s[0] << 56 |
              (uint64_t) s[1] << 48 |
              (uint64_t) s[2] << 40 |
              (uint64_t) s[3] << 32 |
              (uint64_t) s[4] << 24 |
              (uint64_t) s[5] << 16 |
              (uint64_t) s[6] << 8 |
              (uint64_t) s[7];
        ans = ans % plain_modulus_.value();
        ans = add_uint_uint_mod(ans, multiply_uint_uint_mod(t, k.cw_last, plain_modulus_), plain_modulus_);
        if (!server_id_) {
            ans = seal::util::negate_uint_mod(ans, plain_modulus_);
        }
        return ans;
    }

    uint64_t FSSEvaluator::dif(const DIFKey &k, uint64_t x) {
        u_char s[16];
        memcpy(s, k.s, 16);
        u_char t = k.t;
        uint64_t v = 0;

        u_char sArray[32];
        u_char temp[2];
        u_char out[64];
        uint64_t temp_v;

        for (size_t i = 0; i < num_bits_; i++) {
            auto xi = get_bit(x, (64 - num_bits_ + i + 1));

            // Generate PRF.
            prf_->generate(s, 64, out);

            memcpy(sArray, out, 32);
            temp[0] = out[32] % 2;
            temp[1] = out[33] % 2;

            temp_v = byte_array_to_integer((u_char *) (out + 40 + (8 * xi))) % plain_modulus_.value();

            auto xStart = 16 * xi;
            memcpy(s, (u_char *) (sArray + xStart), 16);

            for (size_t j = 0; j < 16; j++) {
                s[j] = s[j] ^ (k.cw[i].cs[j] * t);
            }

            v = add_uint_uint_mod(v, temp_v, plain_modulus_);
            v = add_uint_uint_mod(v, k.cw[i].cv[xi] * t, plain_modulus_);

            t = temp[xi] ^ (k.cw[i].ct[xi] * t);
        }

        if (server_id_) {
            v = negate_uint_mod(v, plain_modulus_);
        }

        return v % plain_modulus_.value();
    }

    uint64_t FSSEvaluator::dif_spline(const DIFKey &k, uint64_t x) {
        u_char s[16];
        memcpy(s, k.s, 16);
        u_char t = k.t;
        uint64_t v = 0;

        u_char sArray[32];
        u_char temp[2];
        u_char out[64];
        uint64_t temp_v;

        for (size_t i = 0; i < num_bits_; i++) {
            auto xi = get_bit(x, (64 - num_bits_ + i + 1));

            // Generate PRF.
            prf_->generate(s, 64, out);

            memcpy(sArray, out, 32);
            temp[0] = out[32] % 2;
            temp[1] = out[33] % 2;

            temp_v = byte_array_to_integer((u_char *) (out + 40 + (8 * xi))) % plain_modulus_spline_.value();

            auto xStart = 16 * xi;
            memcpy(s, (u_char *) (sArray + xStart), 16);

            for (size_t j = 0; j < 16; j++) {
                s[j] = s[j] ^ (k.cw[i].cs[j] * t);
            }

            v = add_uint_uint_mod(v, temp_v, plain_modulus_spline_);
            v = add_uint_uint_mod(v, k.cw[i].cv[xi] * t, plain_modulus_spline_);

            t = temp[xi] ^ (k.cw[i].ct[xi] * t);
        }

        if (server_id_) {
            v = negate_uint_mod(v, plain_modulus_spline_);
        }

        return v % plain_modulus_spline_.value();
    }

    uint64_t FSSEvaluator::relu(const ReLUKey &relu_key, uint64_t blinded_input) {
        auto f1 = dif(relu_key.f[0], blinded_input) % plain_modulus_.value();
        auto f2 = dif(relu_key.f[1], blinded_input) % plain_modulus_.value();
        auto f3 = dif(relu_key.f[2], blinded_input) % plain_modulus_.value();

        auto g1 = dif(relu_key.g[0], blinded_input) % plain_modulus_.value();
        auto g2 = dif(relu_key.g[1], blinded_input) % plain_modulus_.value();
        auto g3 = dif(relu_key.g[2], blinded_input) % plain_modulus_.value();

        auto c0 = add_uint_uint_mod(add_uint_uint_mod(f1, f2, plain_modulus_), f3, plain_modulus_);
        auto c1 = add_uint_uint_mod(add_uint_uint_mod(g1, g2, plain_modulus_), g3, plain_modulus_);
        auto y = add_uint_uint_mod(multiply_uint_uint_mod(blinded_input, c0, plain_modulus_), c1, plain_modulus_);

        return y % plain_modulus_.value();
    }
}
