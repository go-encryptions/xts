//go:build amd64

package xts

import "golang.org/x/sys/cpu"

// accelAvailable reports whether the fused assembly AES-XTS kernel can be used
// on this amd64 CPU. Unlike arm64, AES-NI is optional on amd64, so we gate on
// the CPUID feature bits. Without AES-NI (and the SSE3/PCLMUL the kernel uses)
// we fall back to the portable per-block path.
var accelAvailable = cpu.X86.HasAES && cpu.X86.HasSSE3

// xtsEncSectorAsm encrypts p in place using AES-XTS (AES-NI), pipelined 4
// blocks wide. See accel_arm64.go for the parameter contract.
//
//go:noescape
func xtsEncSectorAsm(p []byte, enc *byte, rounds int, tweak *byte)

// aesEncBlockAsm encrypts the 16 bytes at p in place with the flat
// encryption schedule enc (rounds+1 keys): the XTS tweak T0 = E_k2(sector).
//
//go:noescape
func aesEncBlockAsm(p *byte, enc *byte, rounds int)

// encTweaks8 encrypts the 8 blocks at p (128 bytes) in place with enc. On
// amd64 it is 8 single-block calls: the batching that pays on arm64 has not
// been written for AES-NI yet, and this keeps one sectorsAccel for both.
func encTweaks8(p *[8 * blockSize]byte, enc *byte, rounds int) {
	for j := 0; j < 8; j++ {
		aesEncBlockAsm(&p[blockSize*j], enc, rounds)
	}
}

// xtsDecSectorAsm decrypts p in place using AES-XTS (AES-NI). dec is the
// AESDEC-ready schedule built by expandDec.
//
//go:noescape
func xtsDecSectorAsm(p []byte, dec *byte, rounds int, tweak *byte)
