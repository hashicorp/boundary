package event

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEventerConfig_validate(t *testing.T) {
	tests := []struct {
		name            string
		c               EventerConfig
		wantErrIs       error
		wantErrContains string
	}{
		{
			name: "invalid-audit-delivery",
			c: EventerConfig{
				AuditDelivery: "invalid",
			},
			wantErrIs:       ErrInvalidParameter,
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
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "is not a valid delivery guarantee",
		},
		{
			name: "valid-observation-delivery",
			c: EventerConfig{
				ObservationDelivery: Enforced,
			},
		},
		{
			name: "invalid-sink",
			c: EventerConfig{
				Sinks: []SinkConfig{
					{
						SinkType: "invalid",
					},
				},
			},
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "is not a valid sink type",
		},
		{
			name: "valid-with-all-defaults",
			c:    EventerConfig{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			err := tt.c.validate()
			if tt.wantErrIs != nil {
				require.Error(err)
				assert.ErrorIs(err, tt.wantErrIs)
				if tt.wantErrContains != "" {
					assert.Contains(err.Error(), tt.wantErrContains)
				}
				return
			}
			assert.NoError(err)
		})
	}
}
