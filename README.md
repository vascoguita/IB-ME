# IB-ME
This repository holds a C implementation of the Identity-Based Matchmaking Encryption scheme by Ateniese et al: "[Match Me if You Can: Matchmaking Encryption and its Applications](https://eprint.iacr.org/2018/1094.pdf)".

The provided library is a transposition of the PoC Python implementation of IB-ME scheme described in the latter paper and available here: https://github.com/cygnusv/matchmaking-encryption.git.

## Disclaimer
This library was developed for prototyping **only**. It was not extensively tested and it can not be considered secure.
Do **not** use it as part of a production setup.

## Dependencies
The IB-ME library is built with [CMake](https://cmake.org/) and depends on the [PBC](https://crypto.stanford.edu/pbc/) and [OpenSSL](https://www.openssl.org/) libraries.

## Build
    cmake .
    make

## Run demo
After building the project you can run the demonstration:

    cd demo
    ./demo

## Run benchmark
After building the project you can run the benchmark program:

    cd benchmark
    ./benchmark -o <operation> -r <number of repetitions>

The benchmark program supports the following operations:

* setup
* sk_gen
* rk_gen
* enc
* dec