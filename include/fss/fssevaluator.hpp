
#pragma once

#include <cmath>

#include <fss/common.hpp>
#include <fss/keys.hpp>
#include <fss/expandingprf.hpp>
#include <fss/fsscontext.hpp>

#include "seal/uintarithsmallmod.h"

using namespace seal::util;

namespace fss {
    class FSSEvaluator {
    public:
        /**
         * Constructs an FSSEvaluator instance with the given FSSContext.
         *
         * @param fss_context The given FSSContext.
         */
        explicit FSSEvaluator(const std::shared_ptr<FSSContext> &fss_context, size_t server_id) {
            // Verify parameters.
            if (!fss_context) {
                throw std::invalid_argument("Invalid FSSContext.");
            }

            fss_context_ = fss_context;
            prf_ = std::make_unique<ExpandingPRF>(fss_context);

            num_bits_ = fss_context_->num_bits();
            plain_modulus_ = fss_context_->plain_modulus();
            plain_modulus_spline_ = SmallModulus(plain_modulus_.value() << 5u);
            server_id_ = server_id;
            scaling_ = fss_context_->scaling();
        }

        uint64_t dpf(const DPFKey &k, uint64_t x);

        uint64_t dif(const DIFKey &k, uint64_t x);

        uint64_t dif_spline(const DIFKey &k, uint64_t x);

        uint64_t relu(const ReLUKey &relu_key, uint64_t blinded_input);

    private:
        std::shared_ptr<FSSContext> fss_context_;

        std::unique_ptr<ExpandingPRF> prf_;

        /*
         * Useful members for computations.
         */
        size_t num_bits_ = 0;

        size_t scaling_ = 0;

        SmallModulus plain_modulus_ = 0;

        SmallModulus plain_modulus_spline_ = 0;

        size_t server_id_ = 0;
    };

}
