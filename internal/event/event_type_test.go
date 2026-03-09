// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package event

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestType_Validate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		eventType  Type
		wantErrMsg string
	}{
		{
			name:       "invalid-event-type",
			eventType:  Type("INVALID_EVENT_TYPE"),
			wantErrMsg: "event.(Type).Validate: 'INVALID_EVENT_TYPE' is not a valid event type: invalid parameter",
		},
		{
			name:      "all-event-types",
			eventType: EveryType,
		},
		{
			name:      "observation-event-type",
			eventType: ObservationType,
		},
		{
			name:      "audit-event-type",
			eventType: AuditType,
		},
		{
			name:      "error-event-type",
			eventType: ErrorType,
		},
		{
			name:      "system-event-type",
			eventType: SystemType,
		},
		{
			name:      "storage-event-type",
			eventType: StorageType,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			err := tt.eventType.Validate()
			if tt.wantErrMsg != "" {
				require.Error(err)
				assert.ErrorContains(err, tt.wantErrMsg)
				return
			}

			require.NoError(err)
		})
	}
}
