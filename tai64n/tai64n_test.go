/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package tai64n

import (
	"encoding/binary"
	"testing"
	"time"
)

// Test that timestamps are monotonic as required by Wireguard and that
// nanosecond-level information is whitened to prevent side channel attacks.
func TestMonotonic(t *testing.T) {
	startTime := time.Unix(0, 123456789) // a nontrivial bit pattern
	// Whitening should reduce timestamp granularity
	// to more than 10 but fewer than 20 milliseconds.
	tests := []struct {
		name      string
		t1, t2    time.Time
		wantAfter bool
	}{
		{"after_10_ns", startTime, startTime.Add(10 * time.Nanosecond), false},
		{"after_10_us", startTime, startTime.Add(10 * time.Microsecond), false},
		{"after_1_ms", startTime, startTime.Add(time.Millisecond), false},
		{"after_10_ms", startTime, startTime.Add(10 * time.Millisecond), false},
		{"after_20_ms", startTime, startTime.Add(20 * time.Millisecond), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts1, ts2 := stamp(tt.t1), stamp(tt.t2)
			got := ts2.After(ts1)
			if got != tt.wantAfter {
				t.Errorf("after = %v; want %v", got, tt.wantAfter)
			}
		})
	}
}

// TestNext checks that Next produces a strictly greater, representable
// timestamp, which is what keeps handshake timestamps increasing across a
// wall clock step.
func TestNext(t *testing.T) {
	tests := []struct {
		name string
		t    time.Time
	}{
		{"zero", time.Unix(0, 0)},
		{"whitened", time.Unix(123456789, 0)},
		{"nanos", time.Unix(123456789, 999999999)},
		{"clean_second", time.Unix(1700000000, 0)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := stamp(tt.t)
			next := ts.Next()
			if !next.After(ts) {
				t.Fatalf("Next() = %v, not after %v", ts, next)
			}
			// Next must be a fixed point of the encoding: it already sits on a
			// whitening boundary, so re-encoding reproduces it exactly.
			if got := stamp(timestampTime(next)); got != next {
				t.Fatalf("Next() is not a fixed point of the encoding: %v != %v", got, next)
			}
		})
	}
}

// timestampTime decodes a timestamp back to a wall clock instant. It exists only
// in the test: production code has no need to decode what it emits.
func timestampTime(t Timestamp) time.Time {
	return time.Unix(int64(binary.BigEndian.Uint64(t[:8])-base), int64(binary.BigEndian.Uint32(t[8:])))
}

// TestNextCarriesSecond verifies the nanosecond field rolls over into seconds
// instead of wrapping to zero inside the same second.
func TestNextCarriesSecond(t *testing.T) {
	// A timestamp within one granule of the next second, so that stepping by
	// one granule crosses the boundary.
	ts := stamp(time.Unix(1700000000, 1e9-1))
	next := ts.Next()
	if timestampTime(next).Unix() != timestampTime(ts).Unix()+1 {
		t.Fatalf("Next() second = %d, want %d", timestampTime(next).Unix(), timestampTime(ts).Unix()+1)
	}
	if binary.BigEndian.Uint32(next[8:]) != 0 {
		t.Fatalf("Next() nanoseconds = %d, want zero", binary.BigEndian.Uint32(next[8:]))
	}
	if !next.After(ts) {
		t.Fatal("Next() did not advance past the second boundary")
	}
}

// TestNextIsStrictlyIncreasing exercises the property the handshake relies on:
// repeated Next calls always move forward, even across many granules.
func TestNextIsStrictlyIncreasing(t *testing.T) {
	ts := stamp(time.Unix(1700000000, 0))
	for i := 0; i < 1000; i++ {
		next := ts.Next()
		if !next.After(ts) {
			t.Fatalf("iteration %d: %v is not after %v", i, next, ts)
		}
		ts = next
	}
}
