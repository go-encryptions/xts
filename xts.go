// Package xts implements the XTS-AES tweakable block-cipher mode (IEEE
// P1619/D16, NIST SP 800-38E) used for full-disk encryption.
//
// It is a drop-in replacement for golang.org/x/crypto/xts: the Cipher type
// exposes the same NewCipher / Encrypt / Decrypt API and produces
// byte-identical ciphertext. The difference is performance. x/crypto/xts drives
// the underlying block cipher one 16-byte block at a time through the
// cipher.Block interface and advances the XTS tweak with a scalar GF(2^128)
// multiply per block; on a CPU with hardware AES this collapses a ~10 GB/s AES
// engine to ~600 MB/s because the per-block interface dispatch defeats the
// pipelined multi-block AES path.
//
// This package instead ships a fused AES-XTS kernel that pipelines four AES
// blocks at a time and folds the tweak XOR into the round pipeline. On arm64
// (ARMv8 AES + NEON) and amd64 (AES-NI) the kernel runs the AESE/AESMC (resp.
// AESENC) pipeline directly, reaching multi-GB/s per core. On the remaining
// architectures (riscv64, loong64, ppc64le, s390x) it transparently falls back
// to the same per-block algorithm as x/crypto/xts, so behaviour is identical
// everywhere; only the speed differs.
//
// XTS provides confidentiality but no authentication, and does not implement
// ciphertext stealing, so each sector must be a multiple of 16 bytes. It is
// intended for disk-sector encryption only.
package xts

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"sync"
)

// blockSize is the AES (and XTS) block size in bytes.
const blockSize = 16

// Cipher is an expanded XTS key. It is safe for concurrent use.
type Cipher struct {
	// k1 encrypts the data blocks, k2 encrypts the tweak. Both are always
	// populated and used by the portable fallback path.
	k1, k2 cipher.Block

	// accelerated reports whether the fused assembly kernel is available and
	// usable for this cipher (AES, on a supported architecture). When false,
	// Encrypt/Decrypt use the portable per-block path via k1.
	accelerated bool

	// enc and dec are the flat AES round-key schedules used by the assembly
	// kernel. dec already has InvMixColumns folded in for the inner rounds.
	enc    []byte
	dec    []byte
	tenc   []byte // encryption schedule of k2, for the tweak
	rounds int
}

// NewCipher creates a Cipher from a function that builds the underlying block
// cipher (which must have a 16-byte block size) and a key that is twice the
// underlying cipher's key length. For AES this is a 32-byte key (AES-128-XTS)
// or a 64-byte key (AES-256-XTS).
func NewCipher(cipherFunc func([]byte) (cipher.Block, error), key []byte) (*Cipher, error) {
	c := new(Cipher)
	var err error
	if c.k1, err = cipherFunc(key[:len(key)/2]); err != nil {
		return nil, err
	}
	if c.k2, err = cipherFunc(key[len(key)/2:]); err != nil {
		return nil, err
	}
	if c.k1.BlockSize() != blockSize {
		return nil, errors.New("xts: cipher does not have a block size of 16")
	}

	// Enable the fused assembly kernel only for AES on a supported
	// architecture. trySetupAccel is defined per architecture: on amd64/arm64
	// it detects AES and builds the round-key schedules; on every other
	// architecture it is a no-op that returns false, so the portable per-block
	// path is used. Keeping the accelerated machinery out of the shared code on
	// unsupported architectures means those builds carry no dead statements.
	c.accelerated = c.trySetupAccel(cipherFunc, key)
	return c, nil
}

// Encrypt encrypts a sector of plaintext into ciphertext using the given sector
// number as the XTS tweak. ciphertext and plaintext must overlap entirely or
// not at all, and len(plaintext) must be a non-zero multiple of 16 bytes.
func (c *Cipher) Encrypt(ciphertext, plaintext []byte, sectorNum uint64) {
	if len(ciphertext) < len(plaintext) {
		panic("xts: ciphertext is smaller than plaintext")
	}
	if len(plaintext)%blockSize != 0 {
		panic("xts: plaintext is not a multiple of the block size")
	}

	// The negated form leaves no statement that only one kind of
	// architecture reaches: the generic build's coverage floor is 100% too.
	if !c.encAccel(ciphertext, plaintext, sectorNum) {
		tweak := c.tweak(sectorNum)
		c.cryptBlocks(ciphertext, plaintext, tweak, true)
		tweakPool.Put(tweak)
	}
}

// Decrypt decrypts a sector of ciphertext into plaintext using the given sector
// number as the XTS tweak. The same overlap and length rules as Encrypt apply.
func (c *Cipher) Decrypt(plaintext, ciphertext []byte, sectorNum uint64) {
	if len(plaintext) < len(ciphertext) {
		panic("xts: plaintext is smaller than ciphertext")
	}
	if len(ciphertext)%blockSize != 0 {
		panic("xts: ciphertext is not a multiple of the block size")
	}

	if !c.decAccel(plaintext, ciphertext, sectorNum) {
		tweak := c.tweak(sectorNum)
		c.cryptBlocks(plaintext, ciphertext, tweak, false)
		tweakPool.Put(tweak)
	}
}

// DecryptSectors decrypts consecutive sectors of sectorSize bytes:
// ciphertext[i*sectorSize:(i+1)*sectorSize] is sector firstSector+i. The
// result is that of calling Decrypt on each sector; on amd64 and arm64 it is
// faster, because the tweaks of 8 sectors are encrypted together instead of
// one serial AES per sector. plaintext and ciphertext must overlap entirely
// or not at all; sectorSize must be a positive multiple of 16 and
// len(ciphertext) a multiple of sectorSize.
func (c *Cipher) DecryptSectors(plaintext, ciphertext []byte, sectorSize int, firstSector uint64) {
	c.sectors(plaintext, ciphertext, sectorSize, firstSector, false)
}

// EncryptSectors is the encryption counterpart of DecryptSectors.
func (c *Cipher) EncryptSectors(ciphertext, plaintext []byte, sectorSize int, firstSector uint64) {
	c.sectors(ciphertext, plaintext, sectorSize, firstSector, true)
}

func (c *Cipher) sectors(dst, src []byte, sectorSize int, first uint64, encrypt bool) {
	if sectorSize <= 0 || sectorSize%blockSize != 0 {
		panic("xts: sector size is not a positive multiple of the block size")
	}
	if len(src)%sectorSize != 0 {
		panic("xts: data is not a whole number of sectors")
	}
	if len(dst) < len(src) {
		panic("xts: output is smaller than input")
	}
	if !c.sectorsAccel(dst, src, sectorSize, first, encrypt) {
		for i := 0; i < len(src); i += sectorSize {
			n := first + uint64(i/sectorSize)
			if encrypt {
				c.Encrypt(dst[i:i+sectorSize], src[i:i+sectorSize], n)
			} else {
				c.Decrypt(dst[i:i+sectorSize], src[i:i+sectorSize], n)
			}
		}
	}
}

// tweakPool holds tweak buffers for the portable path. A tweak on the stack
// escapes to the heap through the cipher.Block call that encrypts it -- one
// allocation per sector, measured: 620 per read of an APFS FileVault file
// against 12 when plain. A pooled buffer is already on the heap.
// golang.org/x/crypto/xts does the same (its tweakPool). The accelerated
// path encrypts its tweak in assembly and needs neither.
var tweakPool = sync.Pool{New: func() any { return new([blockSize]byte) }}

// tweak computes the initial XTS tweak T0 = E_k2(sectorNum) for a sector,
// in a buffer from tweakPool that the caller puts back.
func (c *Cipher) tweak(sectorNum uint64) *[blockSize]byte {
	t := tweakPool.Get().(*[blockSize]byte)
	clear(t[:])
	binary.LittleEndian.PutUint64(t[:8], sectorNum)
	c.k2.Encrypt(t[:], t[:])
	return t
}

// Blocks is implemented by a block cipher that can encrypt or decrypt many
// 16-byte blocks in one call, as in ECB mode, faster than one Encrypt or
// Decrypt per block (go-encryptions/twofish interleaves four blocks). dst
// and src have the same length, a multiple of 16, and overlap entirely or
// not at all.
type Blocks interface {
	EncryptBlocks(dst, src []byte)
	DecryptBlocks(dst, src []byte)
}

// cryptBlocks is the portable XTS path, identical in output to
// golang.org/x/crypto/xts. It is used for non-AES ciphers and on architectures
// without an assembly kernel. A cipher that implements Blocks gets the whole
// sector in one call; any other one block at a time.
func (c *Cipher) cryptBlocks(dst, src []byte, tweak *[blockSize]byte, encrypt bool) {
	if b, ok := c.k1.(Blocks); ok {
		cryptBatch(b, dst, src, tweak, encrypt)
		return
	}
	n := len(src)
	lo, hi := loadTweak(tweak)
	for i := 0; i < n; i += blockSize {
		xorTweak(dst[i:i+blockSize], src[i:i+blockSize], lo, hi)
		if encrypt {
			c.k1.Encrypt(dst[i:i+blockSize], dst[i:i+blockSize])
		} else {
			c.k1.Decrypt(dst[i:i+blockSize], dst[i:i+blockSize])
		}
		xorTweak(dst[i:i+blockSize], dst[i:i+blockSize], lo, hi)
		lo, hi = mul2w(lo, hi)
	}
	storeTweak(tweak, lo, hi)
}

// cryptBatch is cryptBlocks for a Blocks cipher. XTS is
// C_i = E(P_i ^ T_i) ^ T_i, and the T_i depend only on the sector, so the
// three steps can run over the whole sector one after another: XOR every
// tweak in, one EncryptBlocks call, XOR every tweak out again. The tweaks
// are recomputed from T_0 for the second XOR rather than stored, which keeps
// the portable path free of allocations. On return tweak has advanced past
// the sector, as after cryptBlocks.
func cryptBatch(b Blocks, dst, src []byte, tweak *[blockSize]byte, encrypt bool) {
	n := len(src)
	lo0, hi0 := loadTweak(tweak)
	lo, hi := lo0, hi0
	for i := 0; i < n; i += blockSize {
		xorTweak(dst[i:i+blockSize], src[i:i+blockSize], lo, hi)
		lo, hi = mul2w(lo, hi)
	}
	storeTweak(tweak, lo, hi)
	if encrypt {
		b.EncryptBlocks(dst[:n], dst[:n])
	} else {
		b.DecryptBlocks(dst[:n], dst[:n])
	}
	lo, hi = lo0, hi0
	for i := 0; i < n; i += blockSize {
		xorTweak(dst[i:i+blockSize], dst[i:i+blockSize], lo, hi)
		lo, hi = mul2w(lo, hi)
	}
}

// The portable path keeps the tweak as two little-endian 64-bit words, lo
// holding bytes 0-7 and hi bytes 8-15, so that doubling it and XORing it
// into a block cost a few word operations instead of 16 byte loads, shifts
// and stores each. The byte order is that of the tweak buffer, which is
// x/crypto/xts's.

func loadTweak(t *[blockSize]byte) (lo, hi uint64) {
	return binary.LittleEndian.Uint64(t[:8]), binary.LittleEndian.Uint64(t[8:])
}

func storeTweak(t *[blockSize]byte, lo, hi uint64) {
	binary.LittleEndian.PutUint64(t[:8], lo)
	binary.LittleEndian.PutUint64(t[8:], hi)
}

// xorTweak sets dst = src ^ (lo, hi) for one 16-byte block.
func xorTweak(dst, src []byte, lo, hi uint64) {
	_ = src[15]
	_ = dst[15]
	binary.LittleEndian.PutUint64(dst[:8], binary.LittleEndian.Uint64(src[:8])^lo)
	binary.LittleEndian.PutUint64(dst[8:16], binary.LittleEndian.Uint64(src[8:16])^hi)
}

// mul2w is mul2 on the two words: a 128-bit left shift by one, and the
// reduction 0x87 folded into the low byte when bit 127 falls out.
func mul2w(lo, hi uint64) (uint64, uint64) {
	carry := hi >> 63
	hi = hi<<1 | lo>>63
	lo = lo<<1 ^ 0x87*carry
	return lo, hi
}
