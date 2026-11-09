//go:build amd64 || arm64

package xts

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
)

// trySetupAccel enables the fused assembly kernel for this cipher when the
// architecture supports it (accelAvailable), the caller passed AES
// (isAESCipher), and the key length is a valid AES key size. On success it
// builds the flat AES round-key schedules used by the kernel and reports true;
// otherwise it reports false and Encrypt/Decrypt use the portable path.
func (c *Cipher) trySetupAccel(cipherFunc func([]byte) (cipher.Block, error), key []byte) bool {
	dataKey := key[:len(key)/2]
	if accelAvailable && isAESKeyLen(len(dataKey)) && isAESCipher(cipherFunc) {
		c.enc = expandEnc(dataKey)
		c.dec = expandDec(dataKey)
		c.tenc = expandEnc(key[len(key)/2:])
		c.rounds = len(dataKey)/4 + 6
		return true
	}
	return false
}

// tweakAccel writes T0 = E_k2(sectorNum) into t with the assembly block
// encryption. t lives on the caller's stack: the assembly functions are
// noescape, so neither a heap allocation nor tweakPool is needed, and no
// cipher.Block interface call is made per sector.
func (c *Cipher) tweakAccel(t *[blockSize]byte, sectorNum uint64) {
	binary.LittleEndian.PutUint64(t[:8], sectorNum)
	aesEncBlockAsm(&t[0], &c.tenc[0], c.rounds)
}

// encAccel runs the accelerated XTS encryption when this cipher is
// accelerated, returning true. When the cipher is not accelerated it reports
// false so the caller falls back to the portable per-block path. The kernel
// works in place; the copy is skipped when the caller already is.
func (c *Cipher) encAccel(ciphertext, plaintext []byte, sectorNum uint64) bool {
	if !c.accelerated {
		return false
	}
	if len(plaintext) == 0 {
		return true
	}
	var t [blockSize]byte
	c.tweakAccel(&t, sectorNum)
	if &ciphertext[0] != &plaintext[0] {
		copy(ciphertext, plaintext)
	}
	xtsEncSectorAsm(ciphertext[:len(plaintext)], &c.enc[0], c.rounds, &t[0])
	return true
}

// decAccel is the decryption counterpart of encAccel.
func (c *Cipher) decAccel(plaintext, ciphertext []byte, sectorNum uint64) bool {
	if !c.accelerated {
		return false
	}
	if len(ciphertext) == 0 {
		return true
	}
	var t [blockSize]byte
	c.tweakAccel(&t, sectorNum)
	if &plaintext[0] != &ciphertext[0] {
		copy(plaintext, ciphertext)
	}
	xtsDecSectorAsm(plaintext[:len(ciphertext)], &c.dec[0], c.rounds, &t[0])
	return true
}

// sectorsAccel runs DecryptSectors / EncryptSectors on the assembly path:
// the T0 of up to 8 sectors are encrypted by one 8-wide AES pass
// (encTweaks8), so no sector waits for its own serial tweak encryption,
// then each sector goes through the kernel with its tweak.
func (c *Cipher) sectorsAccel(dst, src []byte, sectorSize int, first uint64, encrypt bool) bool {
	if !c.accelerated {
		return false
	}
	if len(src) == 0 {
		return true
	}
	if &dst[0] != &src[0] {
		copy(dst, src)
	}
	n := len(src) / sectorSize
	var t [8 * blockSize]byte
	for s := 0; s < n; s += 8 {
		k := min(8, n-s)
		clear(t[:])
		for j := range k {
			binary.LittleEndian.PutUint64(t[blockSize*j:], first+uint64(s+j))
		}
		encTweaks8(&t, &c.tenc[0], c.rounds)
		for j := range k {
			p := dst[(s+j)*sectorSize : (s+j+1)*sectorSize]
			if encrypt {
				xtsEncSectorAsm(p, &c.enc[0], c.rounds, &t[blockSize*j])
			} else {
				xtsDecSectorAsm(p, &c.dec[0], c.rounds, &t[blockSize*j])
			}
		}
	}
	return true
}

func isAESKeyLen(n int) bool { return n == 16 || n == 24 || n == 32 }

// isAESCipher reports whether cipherFunc is crypto/aes.NewCipher by comparing
// the block produced against a freshly created AES block. This guards the
// accelerated path so that a custom 16-byte block cipher never gets silently
// replaced by AES.
func isAESCipher(cipherFunc func([]byte) (cipher.Block, error)) bool {
	probe := make([]byte, 16)
	b, err := cipherFunc(probe)
	if err != nil {
		return false
	}
	ref, _ := aes.NewCipher(probe)
	// Comparing the encryption of a known vector is the most robust
	// cross-version check of the concrete cipher type.
	var in, gotB, gotRef [16]byte
	for i := range in {
		in[i] = byte(i)
	}
	b.Encrypt(gotB[:], in[:])
	ref.Encrypt(gotRef[:], in[:])
	return gotB == gotRef
}
