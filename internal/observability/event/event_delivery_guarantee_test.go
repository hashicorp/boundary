package event

import (
	"testing"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeliveryGuarantee_validate(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name            string
		g               DeliveryGuarantee
		wantErrMatch    *errors.Template
		wantErrContains string
	}{
		{
			name:            "invalid",
			g:               "invalid",
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "not a valid delivery guarantee",
		},
		{
			name: "BestEffort",
			g:    BestEffort,
		},
		{
			name: "Default",
			g:    DefaultDeliveryGuarantee,
		},
		{
			name: "Enforced",
			g:    Enforced,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			err := tt.g.validate()
			if tt.wantErrMatch != nil {
				require.Error(err)
				assert.Truef(errors.Match(tt.wantErrMatch, err), "wanted %q and got %q", tt.wantErrMatch, err)
				if tt.wantErrContains != "" {
					assert.Contains(err.Error(), tt.wantErrContains)
				}
				return
			}
			require.NoError(err)
		})
	}
}
