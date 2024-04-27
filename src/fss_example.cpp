
#include <fss/fssgenerator.hpp>
#include <fss/fssevaluator.hpp>
#include <fss/prng.hpp>
#include <fss/seal/uintarithsmallmod.h>

using namespace fss;

uint64_t relu_2pc(int64_t input) {
    const uint64_t plain_modulus = 124124124124;

    auto fss_context = FSSContext::Create(plain_modulus, 10);

    FSSGenerator generator(fss_context);
    ReLUKey key_s0, key_s1;
    generator.relu(key_s0, key_s1);

    const auto input_s0 = PRNG::get(plain_modulus);
    const auto input_s1 = seal::util::sub_uint_uint_mod(input, input_s0, plain_modulus);

    const auto blinded_input_s0 = seal::util::add_uint_uint_mod(input_s0, key_s0.r, plain_modulus);
    const auto blinded_input_s1 = seal::util::add_uint_uint_mod(input_s1, key_s1.r, plain_modulus);

    const auto combined_input_s0 = seal::util::add_uint_uint_mod(blinded_input_s0, blinded_input_s1, plain_modulus);
    const auto combined_input_s1 = seal::util::add_uint_uint_mod(blinded_input_s1, blinded_input_s0, plain_modulus);


    FSSEvaluator evaluator1(fss_context, 0);
    const auto output_s0 = evaluator1.relu(key_s0, combined_input_s0);


    FSSEvaluator evaluator2(fss_context, 1);
    const auto output_s1 = evaluator2.relu(key_s1, combined_input_s1);

    const auto output = seal::util::add_uint_uint_mod(output_s0, output_s1, plain_modulus);
    return output;
}


int main() {
    std::vector<int64_t> inputs = {-10, 0, 10};
    for (const auto input: inputs) {
        std::cout << "x: " << input << std::endl;
        const auto output = relu_2pc(input);
        std::cout << "ReLU(x): " << output << std::endl;
    }
}