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
#include <fss/fssgenerator.hpp>
#include <fss/fssevaluator.hpp>

FSSGenerator generator(fss_context);

ReLUKey key_s0, key_s1;
generator.relu(key_s0, key_s1);

FSSEvaluator evaluator1(fss_context, 0);
FSSEvaluator evaluator2(fss_context, 1);
```

## License

[MIT License](LICENSE)