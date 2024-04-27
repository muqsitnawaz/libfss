
#include "fssgenerator.hpp"

using namespace seal::util;

namespace fss {
    void FSSGenerator::dpf(DPFKey &k0, DPFKey &k1, uint64_t a_i, uint64_t b_i) {
        // set bits in keys and allocate memory
        k0.cw.resize(num_bits_);
        k1.cw.resize(num_bits_);

        // Figure out first relevant bit
        // n represents the number of LSB to compare

        // create arrays size (AES_key_size*2 + 2)
        u_char s0[32];
        u_char s1[32];

        // Set initial seeds for PRF
        if (!RAND_bytes((u_char *) s0, 16)) {
            throw std::runtime_error("Random bytes failed.");
        }
        if (!RAND_bytes((u_char *) s1, 16)) {
            throw std::runtime_error("Random bytes failed.");
        }

        u_char t0;
        u_char t1;

        // Figure out initial ts
        // Make sure t0a and t1a are different
        t0 = 0;
        t1 = 1;

        memcpy(k0.s, s0, 16);
        memcpy(k1.s, s1, 16);

        // Pick right keys to put into cipher
        u_char key0[16];
        u_char key1[16];
        memcpy(key0, (u_char *) s0, 16);
        memcpy(key1, (u_char *) s1, 16);

        u_char cs[16];
        u_char ct[2];
        u_char tbit0[2];
        u_char tbit1[2];
        u_char out0[48];
        u_char out1[48];

        int a;
        for (uint32_t i = 0; i < num_bits_; i++) {
            prf_->generate(key0, 48, out0);
            prf_->generate(key1, 48, out1);
            // Reset a and na bits
            a = get_bit(a_i, (64 - num_bits_ + i + 1));

            memcpy(s0, out0, 32);
            memcpy(s1, out1, 32);
            tbit0[0] = out0[32] % 2;
            tbit0[1] = out0[33] % 2;
            tbit1[0] = out1[32] % 2;
            tbit1[1] = out1[33] % 2;

            for (uint32_t j = 0; j < 16; j++) {
                cs[j] = s0[j + 16 * (1 - a)] ^ s1[j + 16 * (1 - a)];
            }

            ct[0] = tbit0[0] ^ tbit1[0] ^ a ^ 1;
            ct[1] = tbit0[1] ^ tbit1[1] ^ a;
            memcpy(k0.cw[i].cs, cs, 16);
            k0.cw[i].ct[0] = ct[0];
            k0.cw[i].ct[1] = ct[1];
            memcpy(k1.cw[i].cs, cs, 16);
            k1.cw[i].ct[0] = ct[0];
            k1.cw[i].ct[1] = ct[1];
            if (t0 == 0) {
                for (uint32_t j = 0; j < 16; j++) {
                    key0[j] = s0[j + 16 * a];
                }
                t0 = tbit0[a];
            } else {
                for (uint32_t j = 0; j < 16; j++) {
                    key0[j] = s0[j + 16 * a] ^ cs[j];
                }
                t0 = tbit0[a] ^ ct[a];
            }
            if (t1 == 0) {
                for (uint32_t j = 0; j < 16; j++) {
                    key1[j] = s1[j + 16 * a];
                }
                t1 = tbit1[a];
            } else {
                for (uint32_t j = 0; j < 16; j++) {
                    key1[j] = s1[j + 16 * a] ^ cs[j];
                }
                t1 = tbit1[a] ^ ct[a];
            }
        }

        uint64_t cw_last, cw_last_temp0, cw_last_temp1;
        cw_last_temp0 = (uint64_t) key0[0] << 56u |
                        (uint64_t) key0[1] << 48u |
                        (uint64_t) key0[2] << 40u |
                        (uint64_t) key0[3] << 32u |
                        (uint64_t) key0[4] << 24u |
                        (uint64_t) key0[5] << 16u |
                        (uint64_t) key0[6] << 8u |
                        (uint64_t) key0[7];
        cw_last_temp1 = (uint64_t) key1[0] << 56u |
                        (uint64_t) key1[1] << 48u |
                        (uint64_t) key1[2] << 40u |
                        (uint64_t) key1[3] << 32u |
                        (uint64_t) key1[4] << 24u |
                        (uint64_t) key1[5] << 16u |
                        (uint64_t) key1[6] << 8u |
                        (uint64_t) key1[7];
        cw_last_temp0 = cw_last_temp0 % plain_modulus_.value();
        cw_last_temp1 = cw_last_temp1 % plain_modulus_.value();

        if (t1 == 0) {
            cw_last = add_uint_uint_mod(sub_uint_uint_mod(b_i, cw_last_temp0, plain_modulus_), cw_last_temp1,
                                        plain_modulus_);
        } else {
            cw_last = sub_uint_uint_mod(cw_last_temp0, add_uint_uint_mod(b_i, cw_last_temp1, plain_modulus_),
                                        plain_modulus_);
        }
        k0.cw_last = cw_last;
        k1.cw_last = cw_last;
    }

    void FSSGenerator::dif(DIFKey &k0, DIFKey &k1, uint64_t a_i, uint64_t b_i) {
        // Set up num_bits and allocate memory
        k0.cw.resize(num_bits_);
        k1.cw.resize(num_bits_);

        // create arrays size (AES_key_size*2 + 2).
        u_char s0[16];
        u_char s1[16];

        // Set initial seeds for PRF.
        if (!RAND_bytes((u_char *) (s0), 16)) {
            throw std::runtime_error("Random bytes failed.");
        }
        if (!RAND_bytes((u_char *) (s1), 16)) {
            throw std::runtime_error("Random bytes failed.");
        }

        u_char t0;
        u_char t1;
        u_char temp;
        if (!RAND_bytes((u_char *) (&temp), 1)) {
            throw std::runtime_error("Random bytes failed.");
        }

        // Figure out initial ts
        // Make sure t0a and t1a are different
        t0 = 0;
        t1 = 1;

        memcpy(k0.s, s0, 16);
        memcpy(k1.s, s1, 16);
        k0.t = t0;
        k1.t = t1;


        u_char out0[64];
        u_char out1[64];

        uint64_t v0[2];
        uint64_t v1[2];

        u_char cs[16];
        u_char ct0;
        u_char ct1;

        uint64_t cv0;
        uint64_t cv1;

        uint64_t a;
        uint64_t na;

        for (size_t i = 0; i < num_bits_; i++) {
            prf_->generate(s0, 64, out0);
            prf_->generate(s1, 64, out1);

            out0[32] = out0[32] % 2;
            out0[33] = out0[33] % 2;
            out1[32] = out1[32] % 2;
            out1[33] = out1[33] % 2;

            v0[0] = byte_array_to_integer((u_char *) (out0 + 40)) % plain_modulus_.value();
            v0[1] = byte_array_to_integer((u_char *) (out0 + 48)) % plain_modulus_.value();
            v1[0] = byte_array_to_integer((u_char *) (out1 + 40)) % plain_modulus_.value();
            v1[1] = byte_array_to_integer((u_char *) (out1 + 48)) % plain_modulus_.value();

            // Reset a and na bits
            a = get_bit(a_i, (64 - num_bits_ + i + 1));
            na = a ^ 1u;

            // Redefine aStart and naStart based on new a's
            uint64_t naStart = 16 * na;

            // cs
            for (size_t j = 0; j < 16; j++) {
                cs[j] = out0[naStart + j] ^ out1[naStart + j];
            }

            // ct0
            ct0 = out0[32] ^ out1[32] ^ a ^ 1;
            ct1 = out0[33] ^ out1[33] ^ a;

            // cv
            cv0 = sub_uint_uint_mod(
                    sub_uint_uint_mod(v0[0], v1[0], plain_modulus_),
                    multiply_uint_uint_mod(b_i, a, plain_modulus_),
                    plain_modulus_);

            if (t0) {
                cv0 = negate_uint_mod(cv0, plain_modulus_);
            }

            cv1 = sub_uint_uint_mod(v0[1], v1[1], plain_modulus_);
            if (t0) {
                cv1 = negate_uint_mod(cv1, plain_modulus_);
            }

            // Copy appropriate values into key
            memcpy(k0.cw[i].cs, cs, 16);
            k0.cw[i].ct[0] = ct0;
            k0.cw[i].ct[1] = ct1;

            k0.cw[i].cv[0] = cv0;
            k0.cw[i].cv[1] = cv1;

            memcpy(k1.cw[i].cs, cs, 16);
            k1.cw[i].ct[0] = ct0;
            k1.cw[i].ct[1] = ct1;

            k1.cw[i].cv[0] = cv0;
            k1.cw[i].cv[1] = cv1;

            u_char *rs;
            if (a) {
                // update s0
                rs = (u_char *) (out0 + 16);
                for (size_t j = 0; j < 16; j++) {
                    s0[j] = rs[j] ^ (cs[j] * t0);
                }
                rs = (u_char *) (out1 + 16);
                for (size_t j = 0; j < 16; j++) {
                    s1[j] = rs[j] ^ (cs[j] * t1);
                }
                // update  t0 and t1
                t0 = out0[33] ^ (ct1 * t0);
                t1 = out1[33] ^ (ct1 * t1);
            } else {
                rs = (u_char *) (out0);
                for (size_t j = 0; j < 16; j++) {
                    s0[j] = rs[j] ^ (cs[j] * t0);
                }
                rs = (u_char *) (out1);
                for (size_t j = 0; j < 16; j++) {
                    s1[j] = rs[j] ^ (cs[j] * t1);
                }
                t0 = out0[32] ^ (ct0 * t0);
                t1 = out1[32] ^ (ct0 * t1);
            }
        }
    }

    void FSSGenerator::dif_spline(DIFKey &k0, DIFKey &k1, uint64_t a_i, uint64_t b_i) {
        // Set up num_bits and allocate memory
        k0.cw.resize(num_bits_);
        k1.cw.resize(num_bits_);

        // create arrays size (AES_key_size*2 + 2).
        u_char s0[16];
        u_char s1[16];

        // Set initial seeds for PRF.
        if (!RAND_bytes((u_char *) (s0), 16)) {
            throw std::runtime_error("Random bytes failed.");
        }
        if (!RAND_bytes((u_char *) (s1), 16)) {
            throw std::runtime_error("Random bytes failed.");
        }

        u_char t0;
        u_char t1;
        u_char temp;
        if (!RAND_bytes((u_char *) (&temp), 1)) {
            throw std::runtime_error("Random bytes failed.");
        }

        // Figure out initial ts
        // Make sure t0a and t1a are different
        t0 = 0;
        t1 = 1;

        memcpy(k0.s, s0, 16);
        memcpy(k1.s, s1, 16);
        k0.t = t0;
        k1.t = t1;


        u_char out0[64];
        u_char out1[64];

        uint64_t v0[2];
        uint64_t v1[2];

        u_char cs[16];
        u_char ct0;
        u_char ct1;

        uint64_t cv0;
        uint64_t cv1;

        uint64_t a;
        uint64_t na;

        for (size_t i = 0; i < num_bits_; i++) {
            prf_->generate(s0, 64, out0);
            prf_->generate(s1, 64, out1);

            out0[32] = out0[32] % 2;
            out0[33] = out0[33] % 2;
            out1[32] = out1[32] % 2;
            out1[33] = out1[33] % 2;

            v0[0] = byte_array_to_integer((u_char *) (out0 + 40)) % plain_modulus_spline_.value();
            v0[1] = byte_array_to_integer((u_char *) (out0 + 48)) % plain_modulus_spline_.value();
            v1[0] = byte_array_to_integer((u_char *) (out1 + 40)) % plain_modulus_spline_.value();
            v1[1] = byte_array_to_integer((u_char *) (out1 + 48)) % plain_modulus_spline_.value();

            // Reset a and na bits
            a = get_bit(a_i, (64 - num_bits_ + i + 1));
            na = a ^ 1u;

            // Redefine aStart and naStart based on new a's
            uint64_t naStart = 16 * na;

            // cs
            for (size_t j = 0; j < 16; j++) {
                cs[j] = out0[naStart + j] ^ out1[naStart + j];
            }

            // ct0
            ct0 = out0[32] ^ out1[32] ^ a ^ 1;
            ct1 = out0[33] ^ out1[33] ^ a;

            // cv
            cv0 = sub_uint_uint_mod(
                    sub_uint_uint_mod(v0[0], v1[0], plain_modulus_spline_),
                    multiply_uint_uint_mod(b_i, a, plain_modulus_spline_),
                    plain_modulus_spline_);

            if (t0) {
                cv0 = negate_uint_mod(cv0, plain_modulus_spline_);
            }

            cv1 = sub_uint_uint_mod(v0[1], v1[1], plain_modulus_spline_);
            if (t0) {
                cv1 = negate_uint_mod(cv1, plain_modulus_spline_);
            }

            // Copy appropriate values into key
            memcpy(k0.cw[i].cs, cs, 16);
            k0.cw[i].ct[0] = ct0;
            k0.cw[i].ct[1] = ct1;

            k0.cw[i].cv[0] = cv0;
            k0.cw[i].cv[1] = cv1;

            memcpy(k1.cw[i].cs, cs, 16);
            k1.cw[i].ct[0] = ct0;
            k1.cw[i].ct[1] = ct1;

            k1.cw[i].cv[0] = cv0;
            k1.cw[i].cv[1] = cv1;

            u_char *rs;
            if (a) {
                // update s0
                rs = (u_char *) (out0 + 16);
                for (size_t j = 0; j < 16; j++) {
                    s0[j] = rs[j] ^ (cs[j] * t0);
                }
                rs = (u_char *) (out1 + 16);
                for (size_t j = 0; j < 16; j++) {
                    s1[j] = rs[j] ^ (cs[j] * t1);
                }
                // update  t0 and t1
                t0 = out0[33] ^ (ct1 * t0);
                t1 = out1[33] ^ (ct1 * t1);
            } else {
                rs = (u_char *) (out0);
                for (size_t j = 0; j < 16; j++) {
                    s0[j] = rs[j] ^ (cs[j] * t0);
                }
                rs = (u_char *) (out1);
                for (size_t j = 0; j < 16; j++) {
                    s1[j] = rs[j] ^ (cs[j] * t1);
                }
                t0 = out0[32] ^ (ct0 * t0);
                t1 = out1[32] ^ (ct0 * t1);
            }
        }
    }

    void FSSGenerator::relu(ReLUKey &key_s0, ReLUKey &key_s1) {
        // Init PRNG to sample from [0, plain_modulus_).
        std::random_device dev;
        std::mt19937_64 engine(dev());
        std::uniform_int_distribution<uint64_t> dist(0, plain_modulus_.value() - 1);

        // Sample random mask to use for blinding.
        key_s0.r = dist(engine);
        key_s1.r = dist(engine);
        auto rin = add_uint_uint_mod(key_s0.r, key_s1.r, plain_modulus_);

        std::vector<uint64_t> coeffs1{0, 1};
        std::vector<uint64_t> coeffs2{
                negate_uint_mod(multiply_uint_uint_mod(coeffs1[0], rin, plain_modulus_),
                                plain_modulus_),
                negate_uint_mod(multiply_uint_uint_mod(coeffs1[1], rin, plain_modulus_),
                                plain_modulus_)};

        std::vector<uint64_t> intervals{rin % plain_modulus_.value(),
                                        add_uint_uint_mod(rin, plain_mod_by_two_, plain_modulus_)};

        // Shift intervals if rin is negative.
        if (rin >= plain_mod_by_two_) {
            std::rotate(intervals.begin(), intervals.begin() + 1, intervals.end());
            std::rotate(coeffs1.begin(), coeffs1.begin() + 1, coeffs1.end());
            std::rotate(coeffs2.begin(), coeffs2.begin() + 1, coeffs2.end());
        }

        dif(key_s0.f[0], key_s1.f[0],
            intervals[0],
            sub_uint_uint_mod(coeffs1[0], coeffs1[1], plain_modulus_));

        dif(key_s0.f[1], key_s1.f[1],
            intervals[1],
            sub_uint_uint_mod(coeffs1[1], coeffs1[0], plain_modulus_));

        dif(key_s0.f[2], key_s1.f[2],
            plain_modulus_.value() + 1,
            coeffs1[0] % plain_modulus_.value());

        dif(key_s0.g[0], key_s1.g[0],
            intervals[0],
            sub_uint_uint_mod(coeffs2[0], coeffs2[1], plain_modulus_));

        dif(key_s0.g[1], key_s1.g[1],
            intervals[1],
            sub_uint_uint_mod(coeffs2[1], coeffs2[0], plain_modulus_));

        dif(key_s0.g[2], key_s1.g[2],
            plain_modulus_.value() + 1,
            coeffs2[0] % plain_modulus_.value());
    }
}
