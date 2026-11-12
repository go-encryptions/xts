package xts

import (
	"bytes"
	"crypto/cipher"
	"testing"

	"golang.org/x/crypto/twofish" //nolint:staticcheck // a non-AES 16-byte cipher, as the reference oracle's input
	xref "golang.org/x/crypto/xts"
)

// batchCipher wraps a block cipher with the Blocks methods, implemented one
// block at a time, and counts the batch calls so a test can tell the batch
// path ran. It is not AES, so NewCipher never accelerates it.
type batchCipher struct {
	cipher.Block
	calls *int
}

func (b batchCipher) EncryptBlocks(dst, src []byte) {
	*b.calls++
	for i := 0; i < len(src); i += blockSize {
		b.Encrypt(dst[i:i+blockSize], src[i:i+blockSize])
	}
}

func (b batchCipher) DecryptBlocks(dst, src []byte) {
	*b.calls++
	for i := 0; i < len(src); i += blockSize {
		b.Decrypt(dst[i:i+blockSize], src[i:i+blockSize])
	}
}

func newTwofish(key []byte) (cipher.Block, error) { return twofish.NewCipher(key) }

// TestBatchMatchesReference: a cipher offering Blocks gets one batch call
// per sector, and the output is x/crypto/xts's over the same cipher used one
// block at a time. Twofish, not the XOR fake: with E = XOR the tweak cancels
// out of E(P^T)^T, so a wrong tweak would pass.
func TestBatchMatchesReference(t *testing.T) {
	key := make([]byte, 64)
	for i := range key {
		key[i] = byte(7*i + 3)
	}
	calls := 0
	newBatch := func(k []byte) (cipher.Block, error) {
		b, err := twofish.NewCipher(k)
		return batchCipher{b, &calls}, err
	}
	ours, err := NewCipher(newBatch, key)
	if err != nil {
		t.Fatal(err)
	}
	if ours.accelerated {
		t.Fatal("a Twofish cipher must not take the AES kernel")
	}
	ref, err := xref.NewCipher(newTwofish, key)
	if err != nil {
		t.Fatal(err)
	}
	for _, size := range []int{16, 48, 512, 4096} {
		pt := make([]byte, size)
		for i := range pt {
			pt[i] = byte(i*13 + size)
		}
		for _, sec := range []uint64{0, 1, 1<<32 + 5} {
			want := make([]byte, size)
			ref.Encrypt(want, pt, sec)

			calls = 0
			got := make([]byte, size)
			ours.Encrypt(got, pt, sec)
			if calls != 1 {
				t.Fatalf("size %d: %d EncryptBlocks calls, want 1", size, calls)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("size %d sector %d: batch encryption differs from x/crypto/xts", size, sec)
			}

			inPlace := append([]byte(nil), got...)
			calls = 0
			ours.Decrypt(inPlace, inPlace, sec)
			if calls != 1 {
				t.Fatalf("size %d: %d DecryptBlocks calls, want 1", size, calls)
			}
			if !bytes.Equal(inPlace, pt) {
				t.Fatalf("size %d sector %d: in-place batch decryption does not round-trip", size, sec)
			}
		}
	}

	// Sectors: one batch call per sector, same bytes as per-sector calls.
	data := make([]byte, 4*512)
	for i := range data {
		data[i] = byte(i)
	}
	want := make([]byte, len(data))
	for s := 0; s < 4; s++ {
		ref.Encrypt(want[s*512:(s+1)*512], data[s*512:(s+1)*512], uint64(100+s))
	}
	got := make([]byte, len(data))
	calls = 0
	ours.EncryptSectors(got, data, 512, 100)
	if calls != 4 || !bytes.Equal(got, want) {
		t.Fatalf("EncryptSectors: %d batch calls (want 4), equal=%v", calls, bytes.Equal(got, want))
	}
}

// batchPair is a Blocks Twofish XTS cipher and x/crypto/xts over the same
// key, for the tests that compare the two.
func batchPair(t *testing.T) (ours *Cipher, ref *xref.Cipher, calls *int) {
	t.Helper()
	key := make([]byte, 64)
	for i := range key {
		key[i] = byte(5*i + 1)
	}
	calls = new(int)
	newBatch := func(k []byte) (cipher.Block, error) {
		b, err := twofish.NewCipher(k)
		return batchCipher{b, calls}, err
	}
	var err error
	if ours, err = NewCipher(newBatch, key); err != nil {
		t.Fatal(err)
	}
	if ref, err = xref.NewCipher(newTwofish, key); err != nil {
		t.Fatal(err)
	}
	return ours, ref, calls
}

// TestBatchEverySize compares both directions with x/crypto/xts, out of
// place, at every size from one block to 4096 bytes.
func TestBatchEverySize(t *testing.T) {
	ours, ref, _ := batchPair(t)
	for size := blockSize; size <= 4096; size += blockSize {
		pt := make([]byte, size)
		for i := range pt {
			pt[i] = byte(i*29 + size)
		}
		sec := uint64(size) * 977
		want := make([]byte, size)
		ref.Encrypt(want, pt, sec)
		got := make([]byte, size)
		ours.Encrypt(got, pt, sec)
		if !bytes.Equal(got, want) {
			t.Fatalf("Encrypt size %d differs from x/crypto/xts", size)
		}
		wantPT := make([]byte, size)
		ref.Decrypt(wantPT, want, sec)
		gotPT := make([]byte, size)
		ours.Decrypt(gotPT, want, sec)
		if !bytes.Equal(gotPT, wantPT) {
			t.Fatalf("Decrypt size %d differs from x/crypto/xts", size)
		}
	}
}

// TestBatchDecryptSectors: DecryptSectors over 8 sectors equals x/crypto/xts
// sector by sector, with one batch call per sector.
func TestBatchDecryptSectors(t *testing.T) {
	ours, ref, calls := batchPair(t)
	const n, size = 8, 512
	ct := make([]byte, n*size)
	for i := range ct {
		ct[i] = byte(i * 11)
	}
	want := make([]byte, len(ct))
	for s := 0; s < n; s++ {
		ref.Decrypt(want[s*size:(s+1)*size], ct[s*size:(s+1)*size], uint64(40+s))
	}
	got := make([]byte, len(ct))
	*calls = 0
	ours.DecryptSectors(got, ct, size, 40)
	if *calls != n || !bytes.Equal(got, want) {
		t.Fatalf("DecryptSectors: %d batch calls (want %d), equal=%v", *calls, n, bytes.Equal(got, want))
	}
}

// TestBatchNoAlloc: the batch path allocates nothing per call, as the
// per-block path does not. Not under -race, where sync.Pool drops the
// pooled tweak on purpose (see raceEnabled).
func TestBatchNoAlloc(t *testing.T) {
	if raceEnabled {
		t.Skip("sync.Pool drops items under -race; allocation counts are checked without it")
	}
	ours, _, _ := batchPair(t)
	buf := make([]byte, 4096)
	for name, f := range map[string]func(){
		"Encrypt":        func() { ours.Encrypt(buf[:512], buf[:512], 7) },
		"Decrypt":        func() { ours.Decrypt(buf[:512], buf[:512], 7) },
		"DecryptSectors": func() { ours.DecryptSectors(buf, buf, 512, 7) },
	} {
		if n := testing.AllocsPerRun(100, f); n != 0 {
			t.Errorf("%s: %v allocations per call, want 0", name, n)
		}
	}
}
