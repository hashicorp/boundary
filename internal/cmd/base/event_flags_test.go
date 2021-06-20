package base

import (
	"testing"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/observability/event"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEventFlags_Validate(t *testing.T) {
	tests := []struct {
		name            string
		flags           EventFlags
		wantErr         bool
		wantErrContains string
		wantErrMatch    *errors.Template
	}{
		{
			name: "valid-JsonFormat",
			flags: EventFlags{
				Format: event.JSONSinkFormat,
			},
		},
		{
			name:            "empty",
			flags:           EventFlags{},
			wantErr:         true,
			wantErrContains: "not a valid sink format",
			wantErrMatch:    errors.T(errors.InvalidParameter),
		},
		{
			name: "invalid-format",
			flags: EventFlags{
				Format: "invalid-format",
			},
			wantErr:         true,
			wantErrContains: "not a valid sink format",
			wantErrMatch:    errors.T(errors.InvalidParameter),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			err := tt.flags.Validate()
			if tt.wantErr {
				require.Error(err)
				if tt.wantErrMatch != nil {
					assert.Truef(errors.Match(tt.wantErrMatch, err), "want %q and got %q", tt.wantErrMatch, err)
				}
				if tt.wantErrContains != "" {
					assert.Contains(err.Error(), tt.wantErrContains)
				}
				return
			}
			require.NoError(err)
		})
	}

}
