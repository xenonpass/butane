# Contributing to butane

Thank you for your interest in contributing to **butane**! Whether it's a bug fix, a new feature, improved documentation, or a security report — every contribution matters.

---

## Table of Contents

1. [Code of Conduct](#code-of-conduct)
2. [Getting Started](#getting-started)
3. [Development Setup](#development-setup)
4. [Testing](#testing)
5. [Security Vulnerabilities](#security-vulnerabilities)
6. [License](#license)

---

## Code of Conduct

By participating in this project, you agree to maintain a respectful, inclusive, and harassment-free environment. Be kind, constructive, and professional in all interactions.

---

## Getting Started

1. **Fork** the repository on GitHub.
2. **Clone** your fork locally:
   ```bash
   git clone https://github.com/ur-username/butane.git
   cd butane
   ```
3. Make your changes, write tests, and ensure everything passes.
4. **Push** your changes and open a [Pull Request](https://github.com/rokybeast/butane/pulls).

---

## Development Setup

### Prerequisites

| Platform | Toolchain |
|----------|-----------|
| Linux    | GCC or Clang, `cppcheck` |
| macOS    | Clang (Xcode), `cppcheck` |
| Windows  | MSVC (Visual Studio) |

### Building

butane supports two build systems. **neomake** is preferred for development:

```bash
# Build everything + lint (preferred)
neomake run all

# Or use Make
make
make test
make lint
```

On Windows:
```cmd
build.bat
```

### Installing neomake (Manually)

```bash
cargo install --locked --git https://github.com/sinisterMage/neomake.git
```
**If you're on Arch**: `yay -S neomake` (*any AUR helper will work*)

---

## Testing

Make tests for any changes in `src/` under `tests/`.

### Running the test suite

```bash
# With neomake
neomake run test

# With Make
make test

# On Windows (after build.bat)
.\build\test_runner.exe
```

### Test expectations

- The full suite currently contains **36 tests** across 4 suites (Context, Blake2b, Argon2id, AEAD).
- All tests should pass on **all three platforms** (Linux, macOS, Windows) before your changes are merged.
- Cryptographic tests should include:
  - **Known-answer tests** (KATs) against published test vectors where possible.
  - **Round-trip tests** (encrypt → decrypt → compare).
  - **Tamper rejection tests** (flip a bit in tag/nonce/ciphertext → verify failure).
  - **Parameter validation** (null pointers, zero lengths, missing keys).

### Linting

```bash
neomake run lint   # or: make lint
```

Your code must pass `cppcheck --enable=all --std=c11` with zero errors. Existing suppressions are listed in `neomake.toml` and `Makefile` — do not add new suppressions without discussion.

---

## Security Vulnerabilities

**Do not open a public issue for security vulnerabilities.**

Please refer to [SECURITY.md](SECURITY.md) for responsible disclosure instructions. Security reports will be acknowledged within 48 hours.

---

## License

By contributing to butane, you agree that your contributions will be licensed under the [Apache License 2.0](LICENSE), the same license that covers the project.

---

Thank you for helping make butane better! 🔥
