<p align="center"><img src="https://raw.githubusercontent.com/go-encryptions/brand/main/social/go-encryptions.png" alt="go-encryptions/xts" width="720"></p>

# go-encryptions/xts

[![ci](https://github.com/go-encryptions/xts/actions/workflows/ci.yml/badge.svg)](https://github.com/go-encryptions/xts/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/go-encryptions/xts.svg)](https://pkg.go.dev/github.com/go-encryptions/xts)
[![License: BSD-3-Clause](https://img.shields.io/badge/License-BSD--3--Clause-blue.svg)](LICENSE)

Pure-Go **XTS-AES** tweakable block-cipher mode (IEEE P1619/D16, [NIST SP 800-38E](https://csrc.nist.gov/pubs/sp/800/38/e/final)), the sector-level disk-encryption mode used by LUKS, APFS FileVault 2, BitLocker and dm-crypt.

It is a **drop-in replacement for `golang.org/x/crypto/xts`**: the `Cipher` type exposes the same `NewCipher` / `Encrypt` / `Decrypt` API and produces byte-identical ciphertext. The difference is performance. `x/crypto/xts` drives the block cipher one 16-byte block at a time through the `cipher.Block` interface, which collapses a hardware AES engine to a fraction of its throughput. This package instead ships a fused AES-XTS kernel that pipelines several AES blocks at a time and folds the tweak XOR into the round pipeline:

- **amd64** (AES-NI) and **arm64** (ARMv8 AES + NEON) run the AESENC / AESE·AESMC pipeline directly in Plan 9 assembly. On arm64 the kernel takes 8 blocks at a time with every round key held in a register.
- **Measured on arm64** (Apple M4 Max, one core, decryption, OpenSSL 3.6.5 on the same core as the reference): AES-128 at 14.4 GB/s on 4 KiB sectors, against 16.7 GB/s for `openssl speed -evp aes-128-xts`. AES-256 reaches 11.3 GB/s against 12.5 GB/s. On 512-byte sectors AES-128 reaches 8.8 GB/s against 12.9 GB/s: there, the cost of each call (the tweak encryption) still shows. `BenchmarkDecrypt` reproduces these numbers.
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

// Many consecutive sectors in one call: sector firstSector+i is
// ciphertext[i*512:(i+1)*512].
c.DecryptSectors(plaintext, ciphertext, 512, firstSector)
c.EncryptSectors(ciphertext, plaintext, 512, firstSector)
```

`Encrypt` and `Decrypt` operate on a whole disk sector at a time; `sectorNum` is the tweak (the sector index). Buffers must be a whole number of 16-byte blocks and at least one block long, matching the `x/crypto/xts` contract.

`DecryptSectors` and `EncryptSectors` give exactly what `Decrypt` and `Encrypt` give sector by sector (`TestSectorsMatchPerSector`). A disk reader that decrypts a run of sectors should use them. On arm64 they encrypt the tweaks of 8 sectors in one 8-wide AES pass. Called once per sector, each sector would instead start by waiting for its own tweak, about ten AES rounds of latency that nothing can overlap. That wait is what small sectors pay the most for.

None of these allocate (`TestNoAllocPerSector`). On amd64 and arm64 the tweak is encrypted in assembly and stays on the stack. The portable path takes its tweak buffer from a `sync.Pool`, as `golang.org/x/crypto/xts` does.

## Guarantees

- **Byte-identical output** to `golang.org/x/crypto/xts` on every architecture, verified in CI against `x/crypto` as a reference oracle.
- **CGO=0, no `unsafe` in the API surface, no external deps** beyond `golang.org/x/sys/cpu` (AES-NI feature detection) and `golang.org/x/crypto` (test-only cross-check).
- **All six 64-bit Go targets** — amd64, arm64, riscv64, loong64, ppc64le and big-endian s390x — are built and tested in CI (native + QEMU), with a 100%-of-statements coverage gate.

## License

BSD-3-Clause © the go-encryptions/xts authors.
