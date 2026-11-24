/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package tai64n

import (
	"bytes"
	"encoding/binary"
	"time"
)

const (
	TimestampSize = 12
	base          = uint64(0x400000000000000a)
	whitenerMask  = uint32(0x1000000 - 1)
)

type Timestamp [TimestampSize]byte

func stamp(t time.Time) Timestamp {
	var tai64n Timestamp
	secs := base + uint64(t.Unix())
	nano := uint32(t.Nanosecond()) &^ whitenerMask
	binary.BigEndian.PutUint64(tai64n[:], secs)
	binary.BigEndian.PutUint32(tai64n[8:], nano)
	return tai64n
}

func Now() Timestamp {
	return stamp(time.Now())
}

// FromTime returns the TAI64N encoding of t. Now is FromTime(time.Now); the
// separate entry point lets callers that hold a specific instant (a high-water
// mark, or a test's synthetic clock) encode it directly.
func FromTime(t time.Time) Timestamp {
	return stamp(t)
}

// Next returns the smallest timestamp that sorts strictly after t and is
// representable by the encoded format. It is used to keep handshake timestamps
// strictly increasing across wall clock steps: the low bits of the nanosecond
// field are whitened away, so at least one whitening unit has to be added for
// the encoded value to change.
func (t Timestamp) Next() Timestamp {
	secs := binary.BigEndian.Uint64(t[:8])
	nano := binary.BigEndian.Uint32(t[8:]) + whitenerMask + 1
	if nano >= 1e9 {
		secs++
		nano = 0
	}
	var next Timestamp
	binary.BigEndian.PutUint64(next[:8], secs)
	binary.BigEndian.PutUint32(next[8:], nano)
	return next
}

func (t1 Timestamp) After(t2 Timestamp) bool {
	return bytes.Compare(t1[:], t2[:]) > 0
}

func (t Timestamp) String() string {
	return time.Unix(int64(binary.BigEndian.Uint64(t[:8])-base), int64(binary.BigEndian.Uint32(t[8:12]))).String()
}
