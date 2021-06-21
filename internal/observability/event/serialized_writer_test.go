package event

import (
	"os"
	"sync"
	"testing"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testBadWriter struct{}

func (b *testBadWriter) Write(p []byte) (int, error) {
	const op = "event.(testBadWriter).Write"
	return 0, errors.New(errors.Internal, op, "write failed")
}

func TestSerializedWriter_Write(t *testing.T) {

	tests := []struct {
		name            string
		s               *serializedWriter
		wantErrMatch    *errors.Template
		wantErrContains string
	}{
		{
			name:            "missing-serializedWriter",
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing serialized writer",
		},
		{
			name: "missing-writer",
			s: &serializedWriter{
				l: new(sync.Mutex),
			},
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing writer",
		},
		{
			name: "missing-lock",
			s: &serializedWriter{
				w: os.Stderr,
			},
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing lock",
		},
		{
			name: "Write-error",
			s: &serializedWriter{
				w: &testBadWriter{},
				l: new(sync.Mutex),
			},
			wantErrMatch:    errors.T(errors.Internal),
			wantErrContains: "write failed",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			n, err := tt.s.Write([]byte("fido"))
			if tt.wantErrMatch != nil {
				require.Error(err)
				require.Empty(n)
				assert.Truef(errors.Match(tt.wantErrMatch, err), "got %q and wanted %q", tt.wantErrMatch.Code, err)
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
