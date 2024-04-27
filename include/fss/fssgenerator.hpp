
#pragma once

#include <random>
#include <cmath>

#include <fss/common.hpp>
#include <fss/fsscontext.hpp>
#include <fss/keys.hpp>
#include <fss/expandingprf.hpp>

#include "seal/uintarithsmallmod.h"

namespace fss {
    class FSSGenerator {
    public:
        /**
         * Constructs an FSSGenerator with given FSSContext.
         *
         * @param fss_context The given FSSContext.
         * @throws std::invalid_argument if FSSContext is invalid.
         */
        explicit FSSGenerator(const std::shared_ptr<FSSContext> &fss_context) {
            if (!fss_context) {
                throw std::invalid_argument("Invalid FSSContext.");
            }

            fss_context_ = fss_context;
            prf_ = std::make_unique<ExpandingPRF>(fss_context);

            num_bits_ = fss_context_->num_bits();
            plain_modulus_ = fss_context_->plain_modulus();
            plain_modulus_spline_ = SmallModulus(plain_modulus_.value() << 5u);
            plain_mod_by_two_ = plain_modulus_.value() >> 1u;
            scaling_ = fss_context_->scaling();
        }


        void dpf(DPFKey &k0, DPFKey &k1, uint64_t a_i, uint64_t b_i);

        void dif(DIFKey &k0, DIFKey &k1, uint64_t a_i, uint64_t b_i);

        void dif_spline(DIFKey &k0, DIFKey &k1, uint64_t a_i, uint64_t b_i);

        void relu(ReLUKey &key_s0, ReLUKey &key_s1);

    private:
        std::shared_ptr<FSSContext> fss_context_;

        std::unique_ptr<ExpandingPRF> prf_;

        /*
         * Useful members for computations.
         */
        size_t num_bits_ = 0;

        uint8_t scaling_ = 0;

        SmallModulus plain_modulus_{};

        SmallModulus plain_modulus_spline_{};

        uint64_t plain_mod_by_two_ = 0;
    };
}
