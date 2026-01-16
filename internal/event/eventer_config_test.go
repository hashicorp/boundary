// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package event

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEventerConfig_Validate(t *testing.T) {
	tests := []struct {
		name            string
		c               EventerConfig
		wantErrIs       error
		wantErrContains string
	}{
		{
			name: "invalid-sink",
			c: EventerConfig{
				Sinks: []*SinkConfig{
					{
						Type: "invalid",
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
		{
			name: "valid-observation-telemetry-flag",
			c: EventerConfig{
				AuditEnabled:        false,
				ObservationsEnabled: true,
				SysEventsEnabled:    false,
				TelemetryEnabled:    true,
			},
		},
		{
			name: "invalid-observation-telemetry-flag",
			c: EventerConfig{
				AuditEnabled:        false,
				ObservationsEnabled: false,
				SysEventsEnabled:    false,
				TelemetryEnabled:    true,
			},
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "telemetry events require observation event to be enabled",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			err := tt.c.Validate()
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
