# Security Design — butane

> **butane** is the cryptographic engine powering [xenonpass](https://github.com/xenonpass/xenonpass). This document describes its security architecture, cryptographic primitives and its trust boundaries.

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Source Layout & Trust Layers](#source-layout--trust-layers)
4. [Cryptographic Primitives](#cryptographic-primitives)
5. [Key Derivation & Lifecycle](#key-derivation--lifecycle)
6. [Encryption Flow (Hybrid AEAD)](#encryption-flow-hybrid-aead)
7. [Hardware Acceleration & Fallbacks](#hardware-acceleration--fallbacks)
8. [Memory Safety](#memory-safety)
9. [Reporting Vulnerabilities](#reporting-vulnerabilities)

---

## Overview

butane is a pure-C cryptographic library compiled to a static archive (`libbutane.a` / `butane.lib`). It is designed with one principle above all else: **no cryptographic shortcuts**. The library exposes a minimal, opinionated API to higher-level xenonpass components, deliberately hiding algorithm selection from the user to ensure the most secure path is always taken.

```

    xenonpass (Frontend [CLI, TUI, WebServer, App, etc.])
        │
        ▼
    libbutane  ◄── this repository (xpass/butane)
        │
        ▼
    OS / Hardware (AES-NI, PCLMULQDQ, or fallback)

```

---

## Architecture

butane is layered. Each layer has a single responsibility and only calls downward.

```mermaid
graph TD
    A["xenonpass consumers\n(CLI, TUI, etc.)"]
    B["Public API\n(include/butane.h)"]
    C["Core Layer\n(src/core)"]
    D["Crypto Layer\n(src/crypto)"]
    E["System Layer\n(src/sys)"]
    F["Hardware\n(AES-NI · PCLMULQDQ · SSE4.1)"]

    A -->|"C ABI"| B
    B --> C
    C --> D
    D --> E
    E -->|"CPU intrinsics"| F
```

**Layer responsibilities:**

| Layer | Path | Responsibility |
|---|---|---|
| Public API | `include/` | Stable ABI exposed to xenonpass |
| Core | `src/core/` | Context management, memory cleaning, and hardware detection |
| Crypto | `src/crypto/` | Algorithm implementations (`AES-GCM`, `Argon2id`, `XChaCha20-Poly1305`) |
| Sys | `src/sys/` | Hardware capability detection (cpuid) |

---

## Source Layout & Trust Layers

```mermaid
graph LR
    subgraph "Untrusted boundary"
        IN["Caller input\n(plaintext, password, salt)"]
    end

    subgraph "butane trust boundary"
        VAL["Input validation\n(src/core)"]
        CRYPT["Crypto primitives\n(src/crypto)"]
        MEM["Secure memory cleaning\n(src/core/clean.c)"]
    end

    subgraph "Output"
        OUT["Ciphertext, Nonce, Tag"]
    end

    IN -->|"validated"| VAL
    VAL -->|"sanitised"| CRYPT
    CRYPT -->|"wipe on exit"| MEM
    MEM --> OUT
```

All data entering butane crosses the validation boundary first. Sensitive buffers—including the master key and salt stored in the context—are wiped using `butane_clean` before the context is freed.

---

## Cryptographic Primitives

butane automatically selects the best available primitive based on hardware support.

```mermaid
flowchart LR
    subgraph "Symmetric Encryption"
        AES["AES-256-GCM\n(Hardware)"]
        CHA["XChaCha20-Poly1305\n(Software Fallback)"]
    end

    subgraph "Key Derivation"
        KDF["Argon2id\n(memory-hard KDF)"]
    end

    subgraph "Random"
        RNG["OS CSPRNG\n(getrandom / SecRandom / BCryptGenRandom)"]
    end

    KDF -->|"256-bit key"| AES
    KDF -->|"256-bit key"| CHA
```

| Primitive | Algorithm | Reason |
|---|---|---|
| Primary AEAD | AES-256-GCM | Hardware-accelerated (AES-NI), constant-time on supported CPUs |
| Fallback AEAD | XChaCha20-Poly1305 | High-security software fallback for CPUs without AES-NI |
| KDF | Argon2id | Memory-hard protection against GPU brute-force attacks |
| Nonce generation | OS CSPRNG | Uses `getrandom` (Linux), `SecRandomCopyBytes` (Apple), or `BCryptGenRandom` (Windows) |

---

## Key Derivation & Lifecycle

Master passwords are stretched into 256-bit keys using Argon2id. Key material is stored within the `butane_ctx` and protected using `mlock` (Unix) or `VirtualLock` (Windows) to prevent swapping to disk.

```mermaid
sequenceDiagram
    participant User as xenonpass caller
    participant Core as src/core
    participant KDF as Argon2id
    participant Cipher as AEAD Dispatch

    User->>Core: butane_init()
    Note right of Core: Detects AES-NI via CPUID
    User->>Core: butane_derive_key(ctx, password, salt, params)
    Core->>KDF: argon2id(password, salt)
    KDF-->>Core: Derived Master Key
    Note right of Core: Key stored in mlocked/VirtualLocked context
    User->>Core: butane_encrypt(ctx, plaintext, ...)
    Core->>Cipher: aes256gcm or xchacha20poly1305
    Core-->>User: (nonce, ciphertext, tag)
    User->>Core: butane_free(ctx)
    Note right of Core: Key wiped with butane_clean()
```

---

## Encryption Flow (AES-256-GCM)

When AES-NI is available, butane uses a 14-round AES-256 implementation.

```mermaid
flowchart TD
    A["Input: plaintext, key, nonce"]
    B["AES-256 Key Schedule\n(14 rounds)"]
    C["CTR mode encryption\nvia hardware AES-NI"]
    D["GHASH over ciphertext\n(PCLMULQDQ hardware)"]
    E["Tag = E(K, J0) XOR GHASH"]
    F["Output: ciphertext, nonce, tag"]

    A --> B
    B --> C
    C --> D
    D --> E
    C --> F
    E --> F
```

---

## Hardware Acceleration & Fallbacks

Unlike libraries that require manual configuration, butane performs runtime hardware detection. If `cpuid` indicates the processor lacks AES-NI support, butane transparently switches to XChaCha20-Poly1305.

```mermaid
graph TD
    Init["butane_init()"]
    Check{"CPUID: AES-NI?"}
    Init --> Check
    Check -->|"Supported"| GCM["Set mode: AES-256-GCM"]
    Check -->|"Not Supported"| CC["Set mode: XChaCha20-Poly1305"]

    GCM --> Lib["Ready for butane_encrypt"]
    CC --> Lib
```

This ensures the highest possible performance on modern systems while maintaining broad compatibility and security on older or alternative hardware.

---

## Memory Safety

butane prioritizes memory hygiene to prevent sensitive data leakage.

| Guarantee | Mechanism |
|---|---|--- |
| Anti-Swap Protection | Master keys and Argon2 work-buffers are locked in RAM via `mlock()` (Unix) or `VirtualLock()` (Windows) |
| Guaranteed Wiping | `butane_clean` uses `explicit_bzero`, `memset_s`, or `SecureZeroMemory` (Windows) to prevent compiler optimization |
| Context Isolation | Sensitive state is encapsulated in `butane_ctx`; internal structures are cleaned on `butane_free` |
| Standard Compliance | Compiled with `-Wall -Wextra -Wpedantic` and `-std=c11` |

---

## Reporting Vulnerabilities

If you discover a security issue in butane, **do not open a public GitHub issue.**

Please report it privately to the xenonpass maintainers:

- Open a [GitHub Security Advisory](https://github.com/xenonpass/butane/security/advisories/new) on this repository.
- We aim to acknowledge reports within **48 hours** and provide a fix or mitigation within **10-12 days** for critical issues.

---

*This document describes the intended security design of butane. Discrepancies between this document and the implementation should be treated as bugs — in either the code or the documentation.*