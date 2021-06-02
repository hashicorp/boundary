package event

import (
	"testing"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEventerConfig_validate(t *testing.T) {
	tests := []struct {
		name            string
		c               EventerConfig
		wantErrMatch    *errors.Template
		wantErrContains string
	}{
		{
			name: "invalid-audit-delivery",
			c: EventerConfig{
				AuditDelivery: "invalid",
			},
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "is not a valid delivery guarantee",
		},
		{
			name: "valid-audit-delivery",
			c: EventerConfig{
				AuditDelivery: Enforced,
			},
		},
		{
			name: "invalid-observation-delivery",
			c: EventerConfig{
				ObservationDelivery: "invalid",
			},
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "is not a valid delivery guarantee",
		},
		{
			name: "valid-observation-delivery",
			c: EventerConfig{
				ObservationDelivery: Enforced,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			err := tt.c.validate()
			if tt.wantErrMatch != nil {
				require.Error(err)
				assert.Truef(errors.Match(tt.wantErrMatch, err), "wanted %q and got %q", tt.wantErrMatch, err)
				if tt.wantErrContains != "" {
					assert.Contains(err.Error(), tt.wantErrContains)
				}
				return
			}
			assert.NoError(err)
		})
	}
}
