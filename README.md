# README.md
```markdown
# Implementation Code for Selective Message Franking
Code artifact for the paper:
**Selective Message Franking: Encouraging Abuse Reports for Metadata-Private Content Moderation**

This repository contains the C/C++ implementation and performance benchmarks for the Selective Message Franking (SMF) scheme.
The benchmarks evaluate runtime computational overhead and payload chunking performance of SMF instantiations under the ECDSA and BLS curves.

## Directory Layout
```
fe_encode.h / fe_encode.c        # Finite field encoding utilities
symmetric.h / symmetric.c        # Symmetric cryptographic primitives
smf_ecdsa.hpp                    # SMF instantiation based on ECDSA
smf_bls.hpp                      # SMF instantiation based on BLS
test_smf_ecdsa_perf.cpp          # Benchmark for ECDSA-based SMF
test_smf_bls_perf.cpp            # Benchmark for BLS-based SMF
stb_image.h / stb_image_write.h  # Image decoding library for image payload test
pexels-724211268-34418112.jpg    # 500KB test image for chunking evaluation
Makefile
README.md
```

## Prerequisites
Test environment reference:
- Ubuntu 20.04
- GCC/G++ 9.4.0
- Intel Core i5-8250U (support AES-NI, AVX2)

Required libraries:
1. **OpenSSL 1.1.1+**
2. **herumi/mcl** (elliptic curve cryptography library)
3. POSIX Threads (usually built-in on Linux)

> Install OpenSSL development library on Ubuntu:
> ```bash
> sudo apt update && sudo apt install libssl-dev
> ```
> Follow official instructions to build and install [herumi/mcl](https://github.com/herumi/mcl).

## Compilation
```bash
make clean
make -j$(nproc)
```
Output binaries:
- `test_smf_ecdsa_perf_opt`
- `test_smf_bls_perf_opt`

> Build configuration notes:
> - Flags: `-O2 -march=native -DNDEBUG`
> - `-march=native` enables CPU-native instruction sets (AES-NI, AVX2). Binaries may not run on other CPUs.
> - Parallel compilation via `-j$(nproc)` only accelerates building, and does not affect runtime performance.

## Run Benchmarks
No command-line arguments are required.
```bash
./test_smf_ecdsa_perf_opt
./test_smf_bls_perf_opt
```

### Output CSV Files
After execution, four CSV files will be generated in the working directory:
- `ecdsa_data_size_curve.csv`
- `ecdsa_block_grad_curve.csv`
- `bls_data_size_curve.csv`
- `bls_block_grad_curve.csv`

Data coverage:
1. Performance with payload sizes ranging from 256 B to 500 KB;
2. Chunking performance using the built-in 500 KB test image (`pexels-724211268-34418112.jpg`).
Records include metrics for both SMF-A and SMF-B variants.

### Modify Iteration Count
The number of benchmark iterations is hardcoded.
Adjust the corresponding constants directly inside:
`test_smf_ecdsa_perf.cpp` and `test_smf_bls_perf.cpp`, then recompile.

## Clean Build Artifacts
```bash
make clean
```

