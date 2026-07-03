//go:build amd64 || arm64

package xts

import (
	"crypto/aes"
	"crypto/cipher"
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
		c.rounds = len(dataKey)/4 + 6
		return true
	}
	return false
}

// encAccel runs the accelerated in-place XTS encryption when this cipher is
// accelerated, returning true. When the cipher is not accelerated it reports
// false so the caller falls back to the portable per-block path.
func (c *Cipher) encAccel(ciphertext, plaintext []byte, tweak *[blockSize]byte) bool {
	if !c.accelerated {
		return false
	}
	copy(ciphertext, plaintext)
	xtsEncSectorAsm(ciphertext[:len(plaintext)], &c.enc[0], c.rounds, &tweak[0])
	return true
}

// decAccel is the decryption counterpart of encAccel.
func (c *Cipher) decAccel(plaintext, ciphertext []byte, tweak *[blockSize]byte) bool {
	if !c.accelerated {
		return false
	}
	copy(plaintext, ciphertext)
	xtsDecSectorAsm(plaintext[:len(ciphertext)], &c.dec[0], c.rounds, &tweak[0])
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
