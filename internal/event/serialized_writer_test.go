// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package event

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var errTestWriteFailed = errors.New("bad write")

type testBadWriter struct{}

func (b *testBadWriter) Write(p []byte) (int, error) {
	const op = "event.(testBadWriter).Write"
	return 0, fmt.Errorf("%s: write failed: %w", op, errTestWriteFailed)
}

func TestSerializedWriter_Write(t *testing.T) {
	tests := []struct {
		name            string
		s               *serializedWriter
		wantErrIs       error
		wantErrContains string
	}{
		{
			name:            "missing-serializedWriter",
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing serialized writer",
		},
		{
			name: "missing-writer",
			s: &serializedWriter{
				l: new(sync.Mutex),
			},
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing writer",
		},
		{
			name: "missing-lock",
			s: &serializedWriter{
				w: os.Stderr,
			},
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing lock",
		},
		{
			name: "write-error",
			s: &serializedWriter{
				w: &testBadWriter{},
				l: new(sync.Mutex),
			},
			wantErrIs:       errTestWriteFailed,
			wantErrContains: "write failed",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			n, err := tt.s.Write([]byte("fido"))
			if tt.wantErrIs != nil {
				require.Error(err)
				require.Empty(n)
				assert.ErrorIs(err, tt.wantErrIs)
				if tt.wantErrContains != "" {
					assert.Contains(err.Error(), tt.wantErrContains)
				}
				return
			}
			require.NoError(err)
			assert.NotEmpty(n)
		})
	}
}
