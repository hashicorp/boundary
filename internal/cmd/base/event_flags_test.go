// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package base

import (
	"testing"

	"github.com/hashicorp/boundary/internal/event"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEventFlags_Validate(t *testing.T) {
	tests := []struct {
		name            string
		flags           EventFlags
		wantErr         bool
		wantErrContains string
		wantErrIs       error
	}{
		{
			name: "valid-JsonFormat",
			flags: EventFlags{
				Format: event.JSONSinkFormat,
			},
		},
		{
			name: "valid-TextFormat",
			flags: EventFlags{
				Format: event.TextSinkFormat,
			},
		},
		{
			name:            "empty",
			flags:           EventFlags{},
			wantErr:         true,
			wantErrContains: "not a valid sink format",
			wantErrIs:       event.ErrInvalidParameter,
		},
		{
			name: "invalid-format",
			flags: EventFlags{
				Format: "invalid-format",
			},
			wantErr:         true,
			wantErrContains: "not a valid sink format",
			wantErrIs:       event.ErrInvalidParameter,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			err := tt.flags.Validate()
			if tt.wantErr {
				require.Error(err)
				if tt.wantErrIs != nil {
					assert.ErrorIs(err, tt.wantErrIs)
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

func Test_NewEventFlags(t *testing.T) {
	setTrue := true
	setFalse := false
	tests := []struct {
		name            string
		defaultFormat   event.SinkFormat
		composedOf      ComposedOfEventArgs
		wantFlags       *EventFlags
		wantErr         bool
		wantErrIs       error
		wantErrContains string
	}{
		{
			name:            "missing-default-format",
			wantErr:         true,
			wantErrContains: "missing default sink format",
		},
		{
			name:            "invalid-default-format",
			defaultFormat:   "invalid-format",
			wantErr:         true,
			wantErrIs:       event.ErrInvalidParameter,
			wantErrContains: "'invalid-format' is not a valid sink format",
		},
		{
			name:          "defaults",
			defaultFormat: "cloudevents-json",
			wantFlags: &EventFlags{
				Format: "cloudevents-json",
			},
		},
		{
			name:          "override-format",
			defaultFormat: "cloudevents-json",
			composedOf:    ComposedOfEventArgs{Format: "cloudevents-text"},
			wantFlags: &EventFlags{
				Format: "cloudevents-text",
			},
		},
		{
			name:          "observations-true",
			defaultFormat: "cloudevents-json",
			composedOf:    ComposedOfEventArgs{Format: "cloudevents-json", Observations: "true"},
			wantFlags: &EventFlags{
				Format:              "cloudevents-json",
				ObservationsEnabled: &setTrue,
			},
		},
		{
			name:          "observations-false",
			defaultFormat: "cloudevents-json",
			composedOf:    ComposedOfEventArgs{Format: "cloudevents-json", Observations: "false"},
			wantFlags: &EventFlags{
				Format:              "cloudevents-json",
				ObservationsEnabled: &setFalse,
			},
		},
		{
			name:          "audit-true",
			defaultFormat: "cloudevents-json",
			composedOf:    ComposedOfEventArgs{Format: "cloudevents-json", Audit: "true"},
			wantFlags: &EventFlags{
				Format:       "cloudevents-json",
				AuditEnabled: &setTrue,
			},
		},
		{
			name:          "audit-false",
			defaultFormat: "cloudevents-json",
			composedOf:    ComposedOfEventArgs{Format: "cloudevents-json", Audit: "false"},
			wantFlags: &EventFlags{
				Format:       "cloudevents-json",
				AuditEnabled: &setFalse,
			},
		},
		{
			name:          "sysevents-true",
			defaultFormat: "cloudevents-json",
			composedOf:    ComposedOfEventArgs{Format: "cloudevents-json", SysEvents: "true"},
			wantFlags: &EventFlags{
				Format:           "cloudevents-json",
				SysEventsEnabled: &setTrue,
			},
		},
		{
			name:          "sysevents-false",
			defaultFormat: "cloudevents-json",
			composedOf:    ComposedOfEventArgs{Format: "cloudevents-json", SysEvents: "false"},
			wantFlags: &EventFlags{
				Format:           "cloudevents-json",
				SysEventsEnabled: &setFalse,
			},
		},
		{
			name:          "telemetry-true",
			defaultFormat: "cloudevents-json",
			composedOf:    ComposedOfEventArgs{Format: "cloudevents-json", Telemetry: "true"},
			wantFlags: &EventFlags{
				Format:           "cloudevents-json",
				TelemetryEnabled: &setTrue,
			},
		},
		{
			name:          "telemetry-false",
			defaultFormat: "cloudevents-json",
			composedOf:    ComposedOfEventArgs{Format: "cloudevents-json", Telemetry: "false"},
			wantFlags: &EventFlags{
				Format:           "cloudevents-json",
				TelemetryEnabled: &setFalse,
			},
		},
		{
			name:          "valid-allow",
			defaultFormat: "cloudevents-json",
			composedOf:    ComposedOfEventArgs{Format: "cloudevents-json", Allow: []string{`"/Data/Header/status" == 401`}},
			wantFlags: &EventFlags{
				Format:       "cloudevents-json",
				AllowFilters: []string{`"/Data/Header/status" == 401`},
			},
		},
		{
			name:            "invalid-allow",
			defaultFormat:   "cloudevents-json",
			composedOf:      ComposedOfEventArgs{Format: "cloudevents-json", Allow: []string{`"/Data/Header/status" $$== 401`}},
			wantErr:         true,
			wantErrContains: "invalid allow filter",
		},
		{
			name:          "valid-deny",
			defaultFormat: "cloudevents-json",
			composedOf:    ComposedOfEventArgs{Format: "cloudevents-json", Deny: []string{`"/Data/Header/status" == 401`}},
			wantFlags: &EventFlags{
				Format:      "cloudevents-json",
				DenyFilters: []string{`"/Data/Header/status" == 401`},
			},
		},
		{
			name:            "invalid-deny",
			defaultFormat:   "cloudevents-json",
			composedOf:      ComposedOfEventArgs{Format: "cloudevents-json", Deny: []string{`"/Data/Header/status" $$== 401`}},
			wantErr:         true,
			wantErrContains: "invalid deny filter",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := NewEventFlags(tt.defaultFormat, tt.composedOf)
			if tt.wantErr {
				require.Error(err)
				assert.Nil(got)
				if tt.wantErrIs != nil {
					assert.ErrorIs(err, tt.wantErrIs)
				}
				if tt.wantErrContains != "" {
					assert.Contains(err.Error(), tt.wantErrContains)
				}
				return
			}
			require.NoError(err)
			assert.NotNil(got)
			assert.Equal(tt.wantFlags, got)
		})
	}
}
