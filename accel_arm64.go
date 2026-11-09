//go:build arm64

package xts

// accelAvailable reports that a fused assembly AES-XTS kernel exists for arm64
// (ARMv8 AES + NEON). All current arm64 hardware that Go targets implements the
// AES crypto extension; the Go runtime requires it, so no feature probe is
// needed.
const accelAvailable = true

// xtsEncSectorAsm encrypts p in place (len a non-zero multiple of 16) using
// AES-XTS. enc is the flat encryption round-key schedule, rounds the AES round
// count (10 for AES-128, 14 for AES-256), and tweak the pre-encrypted initial
// tweak T0; on return *tweak holds the tweak following the last block.
//
//go:noescape
func xtsEncSectorAsm(p []byte, enc *byte, rounds int, tweak *byte)

// aesEncBlockAsm encrypts the 16 bytes at p in place with the flat
// encryption schedule enc (rounds+1 keys): the XTS tweak T0 = E_k2(sector).
//
//go:noescape
func aesEncBlockAsm(p *byte, enc *byte, rounds int)

// encTweaks8 encrypts the 8 blocks at p (128 bytes) in place with enc,
// interleaved 8-wide: the T0 of 8 sectors in the latency of one.
//
//go:noescape
func encTweaks8(p *[8 * blockSize]byte, enc *byte, rounds int)

// xtsDecSectorAsm decrypts p in place using AES-XTS. dec is the AESD-ready
// decryption schedule (InvMixColumns folded into the inner round keys).
//
//go:noescape
func xtsDecSectorAsm(p []byte, dec *byte, rounds int, tweak *byte)
