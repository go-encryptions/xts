package xts

import (
	"bytes"
	"crypto/aes"
	"testing"
)

// TestNoAllocPerSector pins what a sector costs: nothing on the heap. The
// tweak used to escape through the cipher.Block call that computes it, one
// allocation per sector (go-filesystems/apfs counted 620 per FileVault read).
func TestNoAllocPerSector(t *testing.T) {
	for _, keyLen := range []int{32, 64} { // AES-128-XTS and AES-256-XTS
		c, err := NewCipher(aes.NewCipher, bytes.Repeat([]byte{7}, keyLen))
		if err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 4096)
		for _, op := range []struct {
			name string
			f    func()
		}{
			{"Encrypt", func() { c.Encrypt(buf, buf, 42) }},
			{"Decrypt", func() { c.Decrypt(buf, buf, 42) }},
		} {
			if n := testing.AllocsPerRun(100, op.f); n != 0 {
				t.Errorf("AES-%d %s: %.1f allocations per sector, want 0", keyLen*4, op.name, n)
			}
		}
	}
}

// The pooled tweak does not carry one sector's state into the next: the
// same sector encrypts the same way whatever came before.
func TestTweakPoolIsClean(t *testing.T) {
	c, err := NewCipher(aes.NewCipher, bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	want := make([]byte, 512)
	c.Encrypt(want, make([]byte, 512), 1)
	for i := uint64(0); i < 50; i++ {
		c.Encrypt(make([]byte, 512), make([]byte, 512), 1<<40+i)
	}
	got := make([]byte, 512)
	c.Encrypt(got, make([]byte, 512), 1)
	if !bytes.Equal(got, want) {
		t.Fatal("sector 1 encrypted differently after other sectors")
	}
}

func BenchmarkSector4K(b *testing.B) {
	c, _ := NewCipher(aes.NewCipher, bytes.Repeat([]byte{7}, 64))
	buf := make([]byte, 4096)
	b.SetBytes(int64(len(buf)))
	b.ReportAllocs()
	for i := range b.N {
		c.Encrypt(buf, buf, uint64(i))
	}
}
