// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package bsr

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_DecodeTimestamp(t *testing.T) {
	cases := []struct {
		name            string
		nanos           uint32
		wantNanos       int
		wantErr         bool
		wantErrContains string
	}{
		{
			name:      "valid case 1",
			nanos:     uint32(999999999),
			wantNanos: 999999999,
		},
		{
			name:      "valid case 2",
			nanos:     uint32(5),
			wantNanos: 5,
		},
		{
			name:            "nanosecond overflow case 1",
			nanos:           uint32(1000000000),
			wantErr:         true,
			wantErrContains: "bsr.decodeTimestamp: nanosecond value of 1000000000 exceeds the max nanosecond value of 999999999: error decoding timestamp",
		},
		{
			name:            "nanosecond overflow case 2",
			nanos:           uint32(2000000000),
			wantErr:         true,
			wantErrContains: "bsr.decodeTimestamp: nanosecond value of 2000000000 exceeds the max nanosecond value of 999999999: error decoding timestamp",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := make([]byte, timestampSize)
			seconds := uint64(0)
			binary.BigEndian.PutUint64(data[:secondSize], seconds)
			binary.BigEndian.PutUint32(data[secondSize:], tc.nanos)
			got, err := decodeTimestamp(data)
			if tc.wantErr {
				require.Error(t, err)
				assert.EqualError(t, err, tc.wantErrContains)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.wantNanos, got.AsTime().Nanosecond())
		})
	}
}
