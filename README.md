# IB-ME for OPTEE
This repository holds a C implementation of the Identity-Based Matchmaking Encryption scheme by Ateniese et al: "[Match Me if You Can: Matchmaking Encryption and its Applications](https://eprint.iacr.org/2018/1094.pdf)".

The provided library is a transposition of the PoC Python implementation of IB-ME scheme described in the latter paper and available here: https://github.com/cygnusv/matchmaking-encryption.git.

This particular branch holds a port of IB-ME library to [OP-TEE](https://www.op-tee.org).

## Disclaimer
This library was developed for prototyping **only**. It was not extensively tested and it can not be considered secure.
Do **not** use it as part of a production setup.

## Dependencies
The IB-ME library depends on the [PBC](https://crypto.stanford.edu/pbc/) library.

A port of the PBC library to OP-TEE can be found in the following repository:
https://github.com/vascoguita/optee_pbc

You should install the PBC library before building the IB-ME library.
The instructions to do so are available in the above repository.

## Installation instructions
    make CROSS_COMPILE=<cross_compile> PLATFORM=<platform> TA_DEV_KIT_DIR=<ta_dev_kit_dir>
    make install TA_DEV_KIT_DIR=<ta_dev_kit_dir>

## Build demo
After installing the library you can build the demonstration:

    make demo CROSS_COMPILE=<cross_compile> TEEC_EXPORT=<teec_export> PLATFORM=<platform> TA_DEV_KIT_DIR=<ta_dev_kit_dir>