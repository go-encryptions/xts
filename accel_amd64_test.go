//go:build amd64

package xts

import (
	"testing"

	"golang.org/x/sys/cpu"
)

// The kernel uses PEXTRQ and PINSRQ (SSE4.1) as well as AES-NI: the gate must
// never open on a CPU model that has AES without SSE4.1.
func TestAccelGateRequiresSSE41(t *testing.T) {
	if accelAvailable && !(cpu.X86.HasAES && cpu.X86.HasSSE41) {
		t.Fatal("assembly kernel enabled without AES-NI and SSE4.1")
	}
	if want := cpu.X86.HasAES && cpu.X86.HasSSE41; accelAvailable != want {
		t.Fatalf("accelAvailable = %v, want %v", accelAvailable, want)
	}
}
