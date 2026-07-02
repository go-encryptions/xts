<p align="center"><img src="https://raw.githubusercontent.com/go-encryptions/brand/main/social/go-encryptions.png" alt="go-encryptions/xts" width="720"></p>

# go-encryptions/xts

[![ci](https://github.com/go-encryptions/xts/actions/workflows/ci.yml/badge.svg)](https://github.com/go-encryptions/xts/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/go-encryptions/xts.svg)](https://pkg.go.dev/github.com/go-encryptions/xts)
[![License: BSD-3-Clause](https://img.shields.io/badge/License-BSD--3--Clause-blue.svg)](LICENSE)

Pure-Go **XTS-AES** tweakable block-cipher mode (IEEE P1619/D16, [NIST SP 800-38E](https://csrc.nist.gov/pubs/sp/800/38/e/final)), the sector-level disk-encryption mode used by LUKS, APFS FileVault 2, BitLocker and dm-crypt.

It is a **drop-in replacement for `golang.org/x/crypto/xts`**: the `Cipher` type exposes the same `NewCipher` / `Encrypt` / `Decrypt` API and produces byte-identical ciphertext. The difference is performance. `x/crypto/xts` drives the block cipher one 16-byte block at a time through the `cipher.Block` interface, which collapses a hardware AES engine to a fraction of its throughput. This package instead ships a fused AES-XTS kernel that pipelines four AES blocks at a time and folds the tweak XOR into the round pipeline:

- **amd64** (AES-NI) and **arm64** (ARMv8 AES + NEON) run the AESENC / AESE·AESMC pipeline directly in Plan 9 assembly, reaching multi-GB/s per core.
- **riscv64, loong64, ppc64le, s390x** transparently fall back to the same per-block algorithm as `x/crypto/xts`, so behaviour is identical everywhere — only the speed differs.

Built for the [`go-encryptions`](https://github.com/go-encryptions) family; the primary consumers are the full-disk-encryption backends [`go-fde/luks`](https://github.com/go-fde/luks) and [`go-fde/apfs`](https://github.com/go-fde/apfs).

## Install

```sh
go get github.com/go-encryptions/xts
```

## Usage

```go
import (
	"crypto/aes"

	"github.com/go-encryptions/xts"
)

// key is the concatenation of two AES keys (32, 48 or 64 bytes total).
c, err := xts.NewCipher(aes.NewCipher, key)
if err != nil { /* ... */ }

c.Encrypt(ciphertext, plaintext, sectorNum) // one 512/4096-byte sector
c.Decrypt(plaintext, ciphertext, sectorNum)
```

`Encrypt` and `Decrypt` operate on a whole disk sector at a time; `sectorNum` is the tweak (the sector index). Buffers must be a whole number of 16-byte blocks and at least one block long, matching the `x/crypto/xts` contract.

## Guarantees

- **Byte-identical output** to `golang.org/x/crypto/xts` on every architecture, verified in CI against `x/crypto` as a reference oracle.
- **CGO=0, no `unsafe` in the API surface, no external deps** beyond `golang.org/x/sys/cpu` (AES-NI feature detection) and `golang.org/x/crypto` (test-only cross-check).
- **All six 64-bit Go targets** — amd64, arm64, riscv64, loong64, ppc64le and big-endian s390x — are built and tested in CI (native + QEMU), with a 100%-of-statements coverage gate.

## License

BSD-3-Clause © the go-encryptions/xts authors.
