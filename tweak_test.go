package xts

import (
	"math/rand"
	"testing"
)

// mul2Bytes is the byte-wise doubling the portable path used before
// mul2w, kept here as its oracle: x/crypto/xts's algorithm, multiplying
// by x in GF(2^128) with x^128 + x^7 + x^2 + x + 1, bytes little-endian.
func mul2Bytes(tweak *[blockSize]byte) {
	var carryIn byte
	for j := range tweak {
		carryOut := tweak[j] >> 7
		tweak[j] = (tweak[j] << 1) + carryIn
		carryIn = carryOut
	}
	if carryIn != 0 {
		tweak[0] ^= 1<<7 | 1<<2 | 1<<1 | 1
	}
}

// TestMul2wMatchesBytes checks the word form against the byte form over a
// chain of doublings from random starts, plus the carry cases: bit 63 (the
// word boundary) and bit 127 (the reduction).
func TestMul2wMatchesBytes(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	starts := [][blockSize]byte{
		{7: 0x80},  // bit 63: crosses from lo to hi
		{15: 0x80}, // bit 127: reduces into the low byte
		{7: 0x80, 15: 0x80},
		{0: 0xff, 1: 0xff, 2: 0xff, 3: 0xff, 4: 0xff, 5: 0xff, 6: 0xff, 7: 0xff, 8: 0xff, 9: 0xff, 10: 0xff, 11: 0xff, 12: 0xff, 13: 0xff, 14: 0xff, 15: 0xff},
	}
	for range 64 {
		var s [blockSize]byte
		r.Read(s[:])
		starts = append(starts, s)
	}
	for _, s := range starts {
		want := s
		lo, hi := loadTweak(&s)
		for step := range 300 {
			mul2Bytes(&want)
			lo, hi = mul2w(lo, hi)
			var got [blockSize]byte
			storeTweak(&got, lo, hi)
			if got != want {
				t.Fatalf("start %x, step %d: words give %x, bytes %x", s, step, got, want)
			}
		}
	}
}
