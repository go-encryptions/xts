package xts

import (
	"bytes"
	"crypto/aes"
	"fmt"
	"testing"
)

// BenchmarkDecrypt covers what disk readers ask for: 512-byte and 4 KiB
// sectors, AES-128 and AES-256. The reference is OpenSSL on the same core:
// `openssl speed -seconds 2 -bytes 4096 -evp aes-128-xts`.
func BenchmarkDecrypt(b *testing.B) {
	for _, keyLen := range []int{32, 64} {
		for _, n := range []int{512, 4096} {
			b.Run(fmt.Sprintf("AES-%d/%d", keyLen*4, n), func(b *testing.B) {
				c, _ := NewCipher(aes.NewCipher, bytes.Repeat([]byte{7}, keyLen))
				buf := make([]byte, n)
				b.SetBytes(int64(n))
				b.ReportAllocs()
				for i := range b.N {
					c.Decrypt(buf, buf, uint64(i))
				}
			})
		}
	}
}
