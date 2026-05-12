<div align="center">

#  butane · C₄H₁₀

**Zero-dependency cryptographic engine for [xenonpass](https://github.com/xenonpass/xenonpass)**

[![CI (Build)](https://github.com/xenonpass/butane/actions/workflows/ci.yml/badge.svg)](https://github.com/xenonpass/butane/actions/workflows/ci.yml)
[![Lint](https://github.com/xenonpass/butane/actions/workflows/lint.yml/badge.svg)](https://github.com/xenonpass/butane/actions/workflows/lint.yml)
[![Security Scan](https://github.com/xenonpass/butane/actions/workflows/security.yml/badge.svg)](https://github.com/xenonpass/butane/actions/workflows/security.yml)
[![GitHub stars](https://img.shields.io/github/stars/xenonpass/butane?style=flat&color=f5a623)](https://github.com/xenonpass/butane/stargazers)
![C11](https://img.shields.io/badge/std-C11-blue?logo=c&logoColor=white)
![Built with GCC & Clang](https://img.shields.io/badge/built%20with-GCC%20%7C%20Clang%20%7C%20MSVC-informational?logo=llvm&logoColor=white)
[![License](https://img.shields.io/github/license/xenonpass/butane?color=purple)](LICENSE)
[![Made with Neomake](https://img.shields.io/badge/Made%20with-Neomake-orange)](https://github.com/sinisterMage/neomake)

Pure C · No malloc in hot path · Hardware-accelerated · Cross-platform

</div>

---

## What is butane?

butane is a minimal, opinionated cryptographic library written in pure C11 with **zero external dependencies**. It compiles to a static archive (`libbutane.a` / `butane.lib`) and powers the [xenonpass](https://github.com/xenonpass/xenonpass) password manager.

The library intentionally hides algorithm selection from the caller — it performs **runtime hardware detection** at initialization and automatically selects the best available cipher, ensuring the most secure and performant path is always taken without any configuration.

### Highlights

- **AES-256-GCM** via hardware AES-NI intrinsics when available
- **XChaCha20-Poly1305** as a constant-time software fallback
- **Argon2id** memory-hard key derivation (GPU brute-force resistant)
- **OS-native CSPRNG** entropy (`getrandom`, `SecRandomCopyBytes`, `BCryptGenRandom`)
- Memory-locked key material (`mlock` / `VirtualLock`) — keys never hit swap
- Guaranteed buffer wiping via `explicit_bzero` / `SecureZeroMemory` / `memset_s`
- Builds on **Linux**, **macOS**, and **Windows** (MSVC)

---

## Quick Start

### Prerequisites

| Platform | Toolchain |
|----------|-----------|
| Linux    | GCC or Clang |
| macOS    | Clang (Xcode) |
| Windows  | MSVC (Visual Studio) |

### Build

```bash
# with make
make            # build libbutane.a
make test       # run the full test suite (36 tests)
make cli        # build the butane CLI tool
make lint       # run cppcheck

# with neomake
neomake run all  # build everything + lint
neomake run test # build and run the test suite
neomake run cli  # build the CLI tool
neomake run lint # run cppcheck
```

On Windows (MSVC):
```cmd
build.bat
```

You can also pass a different compiler:
```bash
make CC=clang test
```

---

## Project Structure

```
butane/
├── include/
│   └── butane.h            # public API — stable C ABI
├── src/
│   ├── core/               # context lifecycle, memory cleaning
│   │   ├── context.c       #   butane_init / butane_free / mlock
│   │   └── clean.c         #   butane_clean (secure zeroing)
│   ├── crypto/             # all cryptographic primitives
│   │   ├── aead.c          #   encrypt/decrypt dispatch + CSPRNG
│   │   ├── aes256gcm.c     #   AES-256-GCM (AES-NI + PCLMULQDQ)
│   │   ├── chacha20.c      #   XChaCha20-Poly1305 (software)
│   │   ├── argon2id.c      #   Argon2id key derivation
│   │   └── blake2b.c       #   BLAKE2b (used internally by Argon2)
│   ├── sys/
│   │   └── hwdetect.c      #   runtime CPUID / AES-NI detection
│   └── cli/                # human-test CLI (not part of libbutane)
│       ├── main.c          #   command dispatch
│       ├── encrypt.c       #   `butane encrypt` subcommand
│       ├── decrypt.c       #   `butane decrypt` subcommand
│       └── vault.c         #   binary vault file persistence
├── tests/                  # test suite (36 tests)
├── Makefile                # GNU Make build
├── neomake.toml            # neomake build (preferred)
├── build.bat               # Windows MSVC build script
└── SECURITY.md             # full security design document
```

---

## API at a Glance

```c
#include "butane.h"

// initialize — detects hardware, selects best cipher
butane_t ctx = butane_init();

// derive a 256-bit key from a password
butane_derive_key(ctx, password, pw_len, salt, salt_len, &params);

// encrypt
butane_encrypt(ctx, plaintext, pt_len, ciphertext, nonce, tag);

// decrypt (constant-time tag verification)
butane_decrypt(ctx, ciphertext, ct_len, plaintext, nonce, tag);

// cleanup — wipes key material, unlocks memory
butane_free(ctx);
```

All sensitive buffers can be explicitly wiped at any time:
```c
butane_clean(buffer, length);  // guaranteed not optimized away
```

---

## CLI Tool

butane ships with a minimal CLI for manual testing against a local vault file:

```bash
# encrypt text into tests/vault/test.butane
./build/butane encrypt

# decrypt and print the stored text
./build/butane decrypt
```

The vault uses a flat binary format: `[salt:16][nonce:24][tag:16][ciphertext:N]`

---

## Platform Support

| Feature | Linux | macOS | Windows |
|---------|:-----:|:-----:|:-------:|
| AES-256-GCM (AES-NI) | ✅ | ✅ | ✅ |
| XChaCha20-Poly1305 | ✅ | ✅ | ✅ |
| Argon2id KDF | ✅ | ✅ | ✅ |
| Entropy source | `getrandom` | `SecRandomCopyBytes` | `BCryptGenRandom` |
| Memory locking | `mlock` | `mlock` | `VirtualLock` |
| Secure wiping | `explicit_bzero` | `memset_s` | `SecureZeroMemory` |
| CI tested | GCC + Clang | GCC + Clang | MSVC |

---

## CI & Quality

| Workflow | What it does |
|----------|-------------|
| **CI (Build)** | Builds and tests on Ubuntu + macOS with both GCC and Clang; builds on Windows with MSVC |
| **Lint** | Runs `cppcheck --enable=all` across the entire codebase |
| **Security Scan** | Weekly CodeQL analysis for C vulnerabilities |

---

## Security

For the full security architecture, trust boundaries, cryptographic design rationale, and vulnerability reporting instructions, see [**SECURITY.md**](SECURITY.md).

---

## Credits

- [@sinisterMage](https://github.com/sinisterMage) made [neomake](https://github.com/sinisterMage/neomake), the build system used for building and running the tests.

---

## License

Licensed under the [Apache License 2.0](LICENSE).

```
Copyright 2026; Mohammed Sajid Shaik
```
