package xts

import (
	"bytes"
	"testing"

	"github.com/go-encryptions/twofish"
)

// BenchmarkBatchTwofish measures the portable path with a real Blocks
// cipher: a 4 KiB run of 512-byte sectors through go-encryptions/twofish,
// which interleaves four blocks per call. It is what go-fde/veracrypt's
// Twofish volumes cost, minus the volume code.
func BenchmarkBatchTwofish(b *testing.B) {
	c, err := NewCipher(twofish.NewCipher, bytes.Repeat([]byte{3}, 64))
	if err != nil {
		b.Fatal(err)
	}
	buf := make([]byte, 4096)
	b.SetBytes(int64(len(buf)))
	b.ReportAllocs()
	for range b.N {
		c.DecryptSectors(buf, buf, 512, 9)
	}
}
