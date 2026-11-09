//go:build !arm64 && !amd64

package xts

import "crypto/cipher"

// This file provides the architecture-neutral fallbacks for platforms without
// a fused assembly AES-XTS kernel (riscv64, loong64, ppc64le, s390x). The
// accelerated machinery (key-schedule expansion, AES detection, the assembly
// dispatch) lives in accel.go and keyexp.go, both constrained to amd64/arm64,
// so it is not compiled here. Encrypt/Decrypt therefore always take the
// portable per-block path, which is byte-for-byte identical to
// golang.org/x/crypto/xts.

// trySetupAccel never enables acceleration on these architectures.
func (c *Cipher) trySetupAccel(cipherFunc func([]byte) (cipher.Block, error), key []byte) bool {
	return false
}

// encAccel always declines, so Encrypt uses the portable path.
func (c *Cipher) encAccel(ciphertext, plaintext []byte, sectorNum uint64) bool {
	return false
}

// sectorsAccel always declines, so DecryptSectors / EncryptSectors call
// Decrypt / Encrypt per sector.
func (c *Cipher) sectorsAccel(dst, src []byte, sectorSize int, first uint64, encrypt bool) bool {
	return false
}

// decAccel always declines, so Decrypt uses the portable path.
func (c *Cipher) decAccel(plaintext, ciphertext []byte, sectorNum uint64) bool {
	return false
}
