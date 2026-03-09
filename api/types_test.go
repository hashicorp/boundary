// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: MPL-2.0

package api

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTypes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name            string
		json            string
		want            any
		wantErrContains string
	}{
		{
			name: "Duration-valid",
			json: `"12345s"`,
			want: Duration{Duration: 12345000000000},
		},
		{
			name: "Duration-valid-with-float",
			json: `"1.2345s"`,
			want: Duration{Duration: 1234500000},
		},
		{
			name: "Duration-valid",
			json: `"1h"`,
			want: Duration{Duration: 3600000000000},
		},
		{
			name:            "UInt64String-InvalidNumber",
			json:            `"abcd"`,
			want:            Duration{Duration: 0},
			wantErrContains: "invalid duration \"abcd\"",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			var got any
			var err error
			switch tc.want.(type) {
			case Duration:
				var i Duration
				err = json.Unmarshal([]byte(tc.json), &i)
				got = i
			default:
				t.Fatalf("invalid type for test: %s", tc.name)
			}
			if tc.wantErrContains != "" {
				require.Error(err)
				assert.Equal(tc.want, got)
				assert.ErrorContains(err, tc.wantErrContains)
				return
			}
			require.NoError(err)
			assert.Equal(tc.want, got)
		})
	}
}
