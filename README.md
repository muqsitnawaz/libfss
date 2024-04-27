# FSS

FSS implements a two-party Function Secret Sharing protocol that allows non-colluding parties to execute a function
without knowing the original inputs of the user.

The inputs and the function are secret shared between the parties making it information therotic secure against an
adversary (given the non-colluding assumption).

## Theory

- [Function Secret Sharing](https://cs.idc.ac.il/~elette/FunctionSecretSharing.pdf)
- [Function Secret Sharing: Improvements and Extensions](https://eprint.iacr.org/2018/707.pdf)

## Applications

- [Pika: Secure Computation
  using Function Secret Sharing over Rings](https://petsymposium.org/popets/2022/popets-2022-0113.pdf)

## Dependencies

```bash
brew install openssl
```

## Installation

```bash
cmake -S .. -B build
cd build
make
sudo make install
```

This will install the library at `/usr/local/include/fss`.

## Usage

```cpp
#include <fss/fsscontext.hpp>
#include <fss/fssgenerator.hpp>
#include <fss/fssevaluator.hpp>

const auto fss_context = FSSContext::Create(plain_modulus, 10); // Creates a ring of size 2^10

FSSGenerator generator(fss_context); // Used for generating keys

ReLUKey key_p0, key_p1;
generator.relu(key_p0, key_p1);

FSSEvaluator evaluator_p0(fss_context, 0); // Used for evaluating the function
FSSEvaluator evaluator_p1(fss_context, 1); // Used for evaluating the function

const auto output_p0 = evaluator_p0.relu(key_p0, <masked_exchanged_input>);
const auto output_p1 = evaluator_p1.relu(key_p1, <masked_exchanged_input>);

const auto output = (output_p0 + output_p1) % plain_modulus; // Output of the function
```

## License

[MIT License](LICENSE)