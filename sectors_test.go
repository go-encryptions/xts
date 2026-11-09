package xts

import (
	"bytes"
	"crypto/aes"
	"fmt"
	"math/rand"
	"testing"
)

// TestSectorsMatchPerSector: DecryptSectors / EncryptSectors give exactly
// what Decrypt / Encrypt give sector by sector, for every key size, for
// counts that leave 0..7 sectors after the batches of 8, in place or not,
// on the accelerated path and on the portable one.
func TestSectorsMatchPerSector(t *testing.T) {
	rng := rand.New(rand.NewSource(2))
	for _, keyLen := range []int{32, 48, 64} {
		key := make([]byte, keyLen)
		rng.Read(key)
		for _, portable := range []bool{false, true} {
			c, err := NewCipher(aes.NewCipher, key)
			if err != nil {
				t.Fatal(err)
			}
			if portable {
				c.accelerated = false
			}
			for _, ss := range []int{16, 512, 4096} {
				for _, n := range []int{0, 1, 7, 8, 9, 17} {
					name := fmt.Sprintf("key%d/portable=%v/ss%d/n%d", keyLen, portable, ss, n)
					pt := make([]byte, ss*n)
					rng.Read(pt)
					first := rng.Uint64()

					want := make([]byte, len(pt))
					for i := 0; i < n; i++ {
						c.Encrypt(want[i*ss:(i+1)*ss], pt[i*ss:(i+1)*ss], first+uint64(i))
					}
					got := make([]byte, len(pt))
					c.EncryptSectors(got, pt, ss, first)
					if !bytes.Equal(got, want) {
						t.Fatalf("%s: EncryptSectors differs from Encrypt", name)
					}
					back := append([]byte(nil), got...)
					c.DecryptSectors(back, back, ss, first) // in place
					if !bytes.Equal(back, pt) {
						t.Fatalf("%s: DecryptSectors in place does not round-trip", name)
					}
					out := make([]byte, len(pt))
					c.DecryptSectors(out, got, ss, first)
					if !bytes.Equal(out, pt) {
						t.Fatalf("%s: DecryptSectors does not round-trip", name)
					}
				}
			}
		}
	}
}

func TestSectorsRefusals(t *testing.T) {
	c, _ := NewCipher(aes.NewCipher, make([]byte, 32))
	for name, f := range map[string]func(){
		"sector size 0":  func() { c.DecryptSectors(make([]byte, 32), make([]byte, 32), 0, 0) },
		"sector size 24": func() { c.DecryptSectors(make([]byte, 48), make([]byte, 48), 24, 0) },
		"partial sector": func() { c.EncryptSectors(make([]byte, 48), make([]byte, 48), 32, 0) },
		"short output":   func() { c.DecryptSectors(make([]byte, 16), make([]byte, 32), 16, 0) },
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s: no panic", name)
				}
			}()
			f()
		}()
	}
}

// BenchmarkDecryptSectors decrypts 1 MiB of 512-byte sectors in one call,
// as a disk reader does.
func BenchmarkDecryptSectors(b *testing.B) {
	for _, keyLen := range []int{32, 64} {
		for _, ss := range []int{512, 4096} {
			b.Run(fmt.Sprintf("AES-%d/%d", keyLen*4, ss), func(b *testing.B) {
				c, _ := NewCipher(aes.NewCipher, bytes.Repeat([]byte{7}, keyLen))
				buf := make([]byte, 1<<20)
				b.SetBytes(int64(len(buf)))
				b.ReportAllocs()
				for i := range b.N {
					c.DecryptSectors(buf, buf, ss, uint64(i)<<11)
				}
			})
		}
	}
}
