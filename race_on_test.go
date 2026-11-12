//go:build race

package xts

// raceEnabled: under -race, sync.Pool drops a share of its items on
// purpose, so the portable path's pooled tweak is sometimes allocated anew.
// Allocation counts on that path are only asserted without -race.
const raceEnabled = true
