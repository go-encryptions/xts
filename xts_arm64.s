//go:build arm64

#include "textflag.h"

// gf_double doubles the XTS tweak held in NEON register V (16 bytes, stored in
// little-endian order: V.D[0] is the low 64 bits, V.D[1] the high 64 bits).
// It computes V = (V << 1) in GF(2^128) with the XTS reduction polynomial
// x^128 + x^7 + x^2 + x + 1 (constant 0x87). Tmp1/Tmp2 are scratch GPRs.
//
//   lo' = (lo << 1)
//   hi' = (hi << 1) | (lo >> 63)
//   if (hi >> 63) != 0 { lo' ^= 0x87 }
//
// Implemented with general-purpose registers for clarity and correctness; the
// AES rounds dominate, so this is not on the hot path.
#define gf_double(V) \
	VMOV	V.D[0], R14;   \
	VMOV	V.D[1], R15;   \
	LSR	$63, R15, R11; \
	LSR	$63, R14, R12; \
	LSL	$1, R14, R14;  \
	LSL	$1, R15, R15;  \
	ORR	R12, R15, R15; \
	MOVD	$0x87, R13;    \
	MUL	R11, R13, R13; \
	EOR	R13, R14, R14; \
	VMOV	R14, V.D[0];   \
	VMOV	R15, V.D[1]

// ── 8-wide path ─────────────────────────────────────────────────────────────
//
// The main loop takes 8 blocks (128 bytes) at a time. Every round key stays in
// a register for the whole call, aligned on the LAST key: the final key is
// always V30 and the penultimate V29, so AES-128 uses V20..V30, AES-192
// V18..V30 and AES-256 V16..V30, and the three key sizes share one unrolled
// tail of rounds. Data is V0..V7, tweaks V8..V15.
//
// The tweak chain runs in general-purpose registers (R14 = low half, R15 =
// high half), one doubling per block, without a NEON round trip per
// doubling. R13 holds the reduction constant 0x87, which is not a logical
// immediate.

// The Go assembler pastes no tokens, so the labels of the 8-wide path are
// written out in each function; the macros are straight-line code only.

// Key loads for 14, 12 and 10 rounds: rounds+1 keys at R8 into
// V(30-rounds)..V30.
#define keys14 \
	VLD1.P	64(R8), [V16.B16, V17.B16, V18.B16, V19.B16]; \
	VLD1.P	64(R8), [V20.B16, V21.B16, V22.B16, V23.B16]; \
	VLD1.P	64(R8), [V24.B16, V25.B16, V26.B16, V27.B16]; \
	VLD1	(R8), [V28.B16, V29.B16, V30.B16]

#define keys12 \
	VLD1.P	64(R8), [V18.B16, V19.B16, V20.B16, V21.B16]; \
	VLD1.P	64(R8), [V22.B16, V23.B16, V24.B16, V25.B16]; \
	VLD1.P	64(R8), [V26.B16, V27.B16, V28.B16, V29.B16]; \
	VLD1	(R8), [V30.B16]

#define keys10 \
	VLD1.P	64(R8), [V20.B16, V21.B16, V22.B16, V23.B16]; \
	VLD1.P	64(R8), [V24.B16, V25.B16, V26.B16, V27.B16]; \
	VLD1	(R8), [V28.B16, V29.B16, V30.B16]

// gpr_double doubles the tweak held in R14 (low) / R15 (high).
#define gpr_double \
	ASR	$63, R15, R11; \
	AND	R13, R11, R11; \
	LSR	$63, R14, R12; \
	LSL	$1, R14, R14; \
	LSL	$1, R15, R15; \
	ORR	R12, R15, R15; \
	EOR	R11, R14, R14

// put_tweak copies the GPR tweak into V and doubles the GPR tweak.
#define put_tweak(V) \
	VMOV	R14, V.D[0]; \
	VMOV	R15, V.D[1]; \
	gpr_double

#define xor8_tweaks \
	VEOR	V0.B16, V8.B16, V0.B16; \
	VEOR	V1.B16, V9.B16, V1.B16; \
	VEOR	V2.B16, V10.B16, V2.B16; \
	VEOR	V3.B16, V11.B16, V3.B16; \
	VEOR	V4.B16, V12.B16, V4.B16; \
	VEOR	V5.B16, V13.B16, V5.B16; \
	VEOR	V6.B16, V14.B16, V6.B16; \
	VEOR	V7.B16, V15.B16, V7.B16

#define xor8(K) \
	VEOR	V0.B16, K.B16, V0.B16; \
	VEOR	V1.B16, K.B16, V1.B16; \
	VEOR	V2.B16, K.B16, V2.B16; \
	VEOR	V3.B16, K.B16, V3.B16; \
	VEOR	V4.B16, K.B16, V4.B16; \
	VEOR	V5.B16, K.B16, V5.B16; \
	VEOR	V6.B16, K.B16, V6.B16; \
	VEOR	V7.B16, K.B16, V7.B16

#define enc8(K) \
	AESE	K.B16, V0.B16; AESMC	V0.B16, V0.B16; \
	AESE	K.B16, V1.B16; AESMC	V1.B16, V1.B16; \
	AESE	K.B16, V2.B16; AESMC	V2.B16, V2.B16; \
	AESE	K.B16, V3.B16; AESMC	V3.B16, V3.B16; \
	AESE	K.B16, V4.B16; AESMC	V4.B16, V4.B16; \
	AESE	K.B16, V5.B16; AESMC	V5.B16, V5.B16; \
	AESE	K.B16, V6.B16; AESMC	V6.B16, V6.B16; \
	AESE	K.B16, V7.B16; AESMC	V7.B16, V7.B16

#define enc8last(K) \
	AESE	K.B16, V0.B16; AESE	K.B16, V1.B16; \
	AESE	K.B16, V2.B16; AESE	K.B16, V3.B16; \
	AESE	K.B16, V4.B16; AESE	K.B16, V5.B16; \
	AESE	K.B16, V6.B16; AESE	K.B16, V7.B16

#define dec8(K) \
	AESD	K.B16, V0.B16; AESIMC	V0.B16, V0.B16; \
	AESD	K.B16, V1.B16; AESIMC	V1.B16, V1.B16; \
	AESD	K.B16, V2.B16; AESIMC	V2.B16, V2.B16; \
	AESD	K.B16, V3.B16; AESIMC	V3.B16, V3.B16; \
	AESD	K.B16, V4.B16; AESIMC	V4.B16, V4.B16; \
	AESD	K.B16, V5.B16; AESIMC	V5.B16, V5.B16; \
	AESD	K.B16, V6.B16; AESIMC	V6.B16, V6.B16; \
	AESD	K.B16, V7.B16; AESIMC	V7.B16, V7.B16

#define dec8last(K) \
	AESD	K.B16, V0.B16; AESD	K.B16, V1.B16; \
	AESD	K.B16, V2.B16; AESD	K.B16, V3.B16; \
	AESD	K.B16, V4.B16; AESD	K.B16, V5.B16; \
	AESD	K.B16, V6.B16; AESD	K.B16, V7.B16

// tweak_to_gpr moves the tweak in V8 to R14/R15 and sets R13 = 0x87;
// tweak_to_v8 moves it back for the 4-wide and tail code.
#define tweak_to_gpr \
	VMOV	V8.D[0], R14; \
	VMOV	V8.D[1], R15; \
	MOVD	$0x87, R13

#define tweak_to_v8 \
	VMOV	R14, V8.D[0]; \
	VMOV	R15, V8.D[1]

// load8 computes the 8 tweaks, loads 8 blocks at R0 (R7 = R0+64) and XORs
// them with their tweaks; store8 XORs the last key and the tweaks and stores.
#define load8 \
	put_tweak(V8); put_tweak(V9); put_tweak(V10); put_tweak(V11); \
	put_tweak(V12); put_tweak(V13); put_tweak(V14); put_tweak(V15); \
	ADD	$64, R0, R7; \
	VLD1	(R0), [V0.B16, V1.B16, V2.B16, V3.B16]; \
	VLD1	(R7), [V4.B16, V5.B16, V6.B16, V7.B16]; \
	xor8_tweaks

#define store8 \
	xor8(V30); \
	xor8_tweaks; \
	VST1	[V0.B16, V1.B16, V2.B16, V3.B16], (R0); \
	VST1	[V4.B16, V5.B16, V6.B16, V7.B16], (R7); \
	ADD	$128, R0

// func xtsEncSectorAsm(p []byte, enc *byte, rounds int, tweak *byte)
//
// Encrypts p (a multiple of 16 bytes, typically a 512-byte sector) in place
// using AES-XTS. The initial tweak T0 is read from *tweak; on return *tweak
// holds the tweak that follows the last processed block (so the same sector
// buffer can be processed in chunks). enc points to the flat encryption round
// key schedule (16*(rounds+1) bytes, big-endian word layout matching the
// FIPS-197 schedule, directly usable by AESE).
//
// Groups of 8 blocks take the 8-wide path above; what is left (under 128
// bytes) is pipelined 4-wide, then a tail loop handles the final 1-3 blocks.
TEXT ·xtsEncSectorAsm(SB), NOSPLIT, $0-48
	MOVD	p_base+0(FP), R0	// data pointer
	MOVD	p_len+8(FP), R1		// data length
	MOVD	enc+24(FP), R2		// round-key pointer
	MOVD	rounds+32(FP), R3	// round count
	MOVD	tweak+40(FP), R4	// tweak pointer

	VLD1	(R4), [V8.B16]		// V8 = current tweak T

	LSR	$7, R1, R5		// R5 = len / 128
	AND	$127, R1, R1		// R1 = what the 8-wide loop leaves
	CBZ	R5, enc_groups4
	MOVD	R2, R8
	CMP	$12, R3
	BLT	enc_k10
	BEQ	enc_k12
	keys14
	B	enc_kdone
enc_k12:
	keys12
	B	enc_kdone
enc_k10:
	keys10
enc_kdone:
	tweak_to_gpr
enc8_loop:
	load8
	CMP	$12, R3
	BLT	enc8_r10
	BEQ	enc8_r12
	enc8(V16); enc8(V17)
enc8_r12:
	enc8(V18); enc8(V19)
enc8_r10:
	enc8(V20); enc8(V21); enc8(V22); enc8(V23); enc8(V24)
	enc8(V25); enc8(V26); enc8(V27); enc8(V28)
	enc8last(V29)
	store8
	SUBS	$1, R5
	BNE	enc8_loop
	tweak_to_v8

enc_groups4:
	// number of full 4-block groups
	LSR	$6, R1, R5		// R5 = len / 64
	AND	$63, R1, R6		// R6 = len % 64 (remaining bytes)

	CBZ	R5, enc_tail

enc_group_loop:
	// Compute tweaks T0..T3 for the 4 blocks into V8,V9,V10,V11.
	VMOV	V8.B16, V9.B16
	gf_double(V9)	// V9 = T1 = T0<<1
	VMOV	V9.B16, V10.B16
	gf_double(V10)	// V10 = T2
	VMOV	V10.B16, V11.B16
	gf_double(V11)	// V11 = T3

	// Load 4 plaintext blocks.
	VLD1	(R0), [V0.B16, V1.B16, V2.B16, V3.B16]
	// PP = P xor T
	VEOR	V0.B16, V8.B16, V0.B16
	VEOR	V1.B16, V9.B16, V1.B16
	VEOR	V2.B16, V10.B16, V2.B16
	VEOR	V3.B16, V11.B16, V3.B16

	// AES encrypt 4 blocks. Round keys streamed from R2; restore R2 after.
	MOVD	R2, R8			// rk cursor
	SUB	$1, R3, R9		// number of AESE+AESMC rounds (rounds-1)
enc_round_loop:
	VLD1.P	16(R8), [V14.B16]
	AESE	V14.B16, V0.B16
	AESMC	V0.B16, V0.B16
	AESE	V14.B16, V1.B16
	AESMC	V1.B16, V1.B16
	AESE	V14.B16, V2.B16
	AESMC	V2.B16, V2.B16
	AESE	V14.B16, V3.B16
	AESMC	V3.B16, V3.B16
	SUBS	$1, R9
	BNE	enc_round_loop
	// Penultimate round key: AESE only (no MixColumns).
	VLD1.P	16(R8), [V14.B16]
	AESE	V14.B16, V0.B16
	AESE	V14.B16, V1.B16
	AESE	V14.B16, V2.B16
	AESE	V14.B16, V3.B16
	// Final round key: XOR.
	VLD1	(R8), [V14.B16]
	VEOR	V0.B16, V14.B16, V0.B16
	VEOR	V1.B16, V14.B16, V1.B16
	VEOR	V2.B16, V14.B16, V2.B16
	VEOR	V3.B16, V14.B16, V3.B16

	// CC = C xor T
	VEOR	V0.B16, V8.B16, V0.B16
	VEOR	V1.B16, V9.B16, V1.B16
	VEOR	V2.B16, V10.B16, V2.B16
	VEOR	V3.B16, V11.B16, V3.B16
	VST1	[V0.B16, V1.B16, V2.B16, V3.B16], (R0)

	ADD	$64, R0
	// Advance tweak: T <- T3 doubled once more.
	VMOV	V11.B16, V8.B16
	gf_double(V8)
	SUBS	$1, R5
	BNE	enc_group_loop

enc_tail:
	// Handle remaining whole blocks (R6 bytes, each 16).
	LSR	$4, R6, R5		// number of tail blocks
	CBZ	R5, enc_done
enc_tail_loop:
	VLD1	(R0), [V0.B16]
	VEOR	V0.B16, V8.B16, V0.B16
	MOVD	R2, R8
	SUB	$1, R3, R9
enc_tail_round:
	VLD1.P	16(R8), [V14.B16]
	AESE	V14.B16, V0.B16
	AESMC	V0.B16, V0.B16
	SUBS	$1, R9
	BNE	enc_tail_round
	VLD1.P	16(R8), [V14.B16]
	AESE	V14.B16, V0.B16
	VLD1	(R8), [V14.B16]
	VEOR	V0.B16, V14.B16, V0.B16
	VEOR	V0.B16, V8.B16, V0.B16
	VST1	[V0.B16], (R0)
	ADD	$16, R0
	gf_double(V8)
	SUBS	$1, R5
	BNE	enc_tail_loop

enc_done:
	VST1	[V8.B16], (R4)		// store updated tweak
	RET

// func xtsDecSectorAsm(p []byte, dec *byte, rounds int, tweak *byte)
// dec points to the decryption round-key schedule with AESIMC pre-applied to
// the inner round keys (so AESD/AESIMC consume them directly). Layout: the keys
// are in forward order [rk0 .. rkN]; decryption consumes them in reverse.
TEXT ·xtsDecSectorAsm(SB), NOSPLIT, $0-48
	MOVD	p_base+0(FP), R0
	MOVD	p_len+8(FP), R1
	MOVD	dec+24(FP), R2
	MOVD	rounds+32(FP), R3
	MOVD	tweak+40(FP), R4

	VLD1	(R4), [V8.B16]

	LSR	$7, R1, R5		// R5 = len / 128
	AND	$127, R1, R1		// R1 = what the 8-wide loop leaves
	CBZ	R5, dec_groups4
	MOVD	R2, R8
	CMP	$12, R3
	BLT	dec_k10
	BEQ	dec_k12
	keys14
	B	dec_kdone
dec_k12:
	keys12
	B	dec_kdone
dec_k10:
	keys10
dec_kdone:
	tweak_to_gpr
dec8_loop:
	load8
	CMP	$12, R3
	BLT	dec8_r10
	BEQ	dec8_r12
	dec8(V16); dec8(V17)
dec8_r12:
	dec8(V18); dec8(V19)
dec8_r10:
	dec8(V20); dec8(V21); dec8(V22); dec8(V23); dec8(V24)
	dec8(V25); dec8(V26); dec8(V27); dec8(V28)
	dec8last(V29)
	store8
	SUBS	$1, R5
	BNE	dec8_loop
	tweak_to_v8

dec_groups4:
	LSR	$6, R1, R5
	AND	$63, R1, R6
	CBZ	R5, dec_tail

dec_group_loop:
	VMOV	V8.B16, V9.B16
	gf_double(V9)
	VMOV	V9.B16, V10.B16
	gf_double(V10)
	VMOV	V10.B16, V11.B16
	gf_double(V11)

	VLD1	(R0), [V0.B16, V1.B16, V2.B16, V3.B16]
	VEOR	V0.B16, V8.B16, V0.B16
	VEOR	V1.B16, V9.B16, V1.B16
	VEOR	V2.B16, V10.B16, V2.B16
	VEOR	V3.B16, V11.B16, V3.B16

	MOVD	R2, R8
	SUB	$1, R3, R9
dec_round_loop:
	VLD1.P	16(R8), [V14.B16]
	AESD	V14.B16, V0.B16
	AESIMC	V0.B16, V0.B16
	AESD	V14.B16, V1.B16
	AESIMC	V1.B16, V1.B16
	AESD	V14.B16, V2.B16
	AESIMC	V2.B16, V2.B16
	AESD	V14.B16, V3.B16
	AESIMC	V3.B16, V3.B16
	SUBS	$1, R9
	BNE	dec_round_loop
	VLD1.P	16(R8), [V14.B16]
	AESD	V14.B16, V0.B16
	AESD	V14.B16, V1.B16
	AESD	V14.B16, V2.B16
	AESD	V14.B16, V3.B16
	VLD1	(R8), [V14.B16]
	VEOR	V0.B16, V14.B16, V0.B16
	VEOR	V1.B16, V14.B16, V1.B16
	VEOR	V2.B16, V14.B16, V2.B16
	VEOR	V3.B16, V14.B16, V3.B16

	VEOR	V0.B16, V8.B16, V0.B16
	VEOR	V1.B16, V9.B16, V1.B16
	VEOR	V2.B16, V10.B16, V2.B16
	VEOR	V3.B16, V11.B16, V3.B16
	VST1	[V0.B16, V1.B16, V2.B16, V3.B16], (R0)

	ADD	$64, R0
	VMOV	V11.B16, V8.B16
	gf_double(V8)
	SUBS	$1, R5
	BNE	dec_group_loop

dec_tail:
	LSR	$4, R6, R5
	CBZ	R5, dec_done
dec_tail_loop:
	VLD1	(R0), [V0.B16]
	VEOR	V0.B16, V8.B16, V0.B16
	MOVD	R2, R8
	SUB	$1, R3, R9
dec_tail_round:
	VLD1.P	16(R8), [V14.B16]
	AESD	V14.B16, V0.B16
	AESIMC	V0.B16, V0.B16
	SUBS	$1, R9
	BNE	dec_tail_round
	VLD1.P	16(R8), [V14.B16]
	AESD	V14.B16, V0.B16
	VLD1	(R8), [V14.B16]
	VEOR	V0.B16, V14.B16, V0.B16
	VEOR	V0.B16, V8.B16, V0.B16
	VST1	[V0.B16], (R0)
	ADD	$16, R0
	gf_double(V8)
	SUBS	$1, R5
	BNE	dec_tail_loop

dec_done:
	VST1	[V8.B16], (R4)
	RET
