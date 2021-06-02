package event

import (
	"testing"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSinkConfig_validate(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name            string
		sc              SinkConfig
		wantErrMatch    *errors.Template
		wantErrContains string
	}{
		{
			name: "missing-name",
			sc: SinkConfig{
				EventTypes: []Type{EveryType},
				SinkType:   FileSink,
				FileName:   "tmp.file",
				Format:     JSONSinkFormat,
			},
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing sink name",
		},
		{
			name: "missing-EventType",
			sc: SinkConfig{
				Name:     "sink-name",
				SinkType: FileSink,
				FileName: "tmp.file",
				Format:   JSONSinkFormat,
			},
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing event types",
		},
		{
			name: "invalid-EventType",
			sc: SinkConfig{
				Name:       "sink-name",
				EventTypes: []Type{"invalid"},
				SinkType:   FileSink,
				FileName:   "tmp.file",
				Format:     JSONSinkFormat,
			},
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "not a valid event type",
		},
		{
			name: "missing-sink-type",
			sc: SinkConfig{
				Name:       "sink-name",
				EventTypes: []Type{EveryType},
				FileName:   "tmp.file",
				Format:     JSONSinkFormat,
			},
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "not a valid sink type",
		},
		{
			name: "invalid-sink-type",
			sc: SinkConfig{
				Name:       "sink-name",
				EventTypes: []Type{EveryType},
				SinkType:   "invalid",
				FileName:   "tmp.file",
				Format:     JSONSinkFormat,
			},
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "not a valid sink type",
		},
		{
			name: "missing-format",
			sc: SinkConfig{
				Name:       "sink-name",
				SinkType:   FileSink,
				EventTypes: []Type{EveryType},
				FileName:   "tmp.file",
			},
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "not a valid sink format",
		},
		{
			name: "file-sink-with-no-file-name",
			sc: SinkConfig{
				EventTypes: []Type{EveryType},
				SinkType:   FileSink,
				Format:     JSONSinkFormat,
			},
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing sink file name",
		},
		{
			name: "valid",
			sc: SinkConfig{
				Name:       "valid",
				EventTypes: []Type{EveryType},
				SinkType:   FileSink,
				FileName:   "tmp.file",
				Format:     JSONSinkFormat,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			err := tt.sc.validate()
			if tt.wantErrMatch != nil {
				require.Error(err)
				require.Truef(errors.Match(tt.wantErrMatch, err), "wanted %q and got %q", tt.wantErrMatch, err)
				if tt.wantErrContains != "" {
					assert.Contains(err.Error(), tt.wantErrContains)
				}
				return
			}
			assert.NoError(err)
		})
	}

}
