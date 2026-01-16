// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package event

import (
	"bytes"
	"context"
	"sync"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEventer_HclogLoggerAdapter(t *testing.T) {
	t.Parallel()
	require := require.New(t)
	ctx := context.Background()
	buffer := new(bytes.Buffer)
	eventerConfig := EventerConfig{
		AuditEnabled:        true,
		ObservationsEnabled: true,
		SysEventsEnabled:    true,
		Sinks: []*SinkConfig{
			{
				Name:       "test-sink",
				EventTypes: []Type{EveryType},
				Format:     TextHclogSinkFormat,
				Type:       WriterSink,
				WriterConfig: &WriterSinkTypeConfig{
					Writer: buffer,
				},
			},
		},
	}
	testLock := &sync.Mutex{}
	testLogger := hclog.New(&hclog.LoggerOptions{
		Mutex: testLock,
		Name:  "test",
	})
	eventer, err := NewEventer(
		testLogger,
		testLock,
		"TestEventer_HclogLoggerAdapter",
		eventerConfig,
	)
	require.NoError(err)

	// This test sends a series of events through the hclog adapter and
	// validates that we see the ones we expect to see on the other side. It
	// also tests various features such as Named and With to ensure they turn
	// into values on the other side.
	logger, err := NewHclogLogger(ctx, eventer, WithHclogLevel(hclog.Info))
	require.NoError(err)

	tests := []struct {
		name          string
		plainLog      bool
		level         hclog.Level
		shouldNotLog  bool
		logOverride   hclog.Logger
		input         string
		outputSubstrs []string
	}{
		{
			name:          "over-level-error",
			level:         hclog.Error,
			input:         "over-error",
			outputSubstrs: []string{"msg=over-error"},
		},
		{
			name:          "over-level-warn",
			level:         hclog.Warn,
			input:         "over-warn",
			outputSubstrs: []string{"msg=over-warn"},
		},
		{
			name:          "at-level",
			level:         hclog.Info,
			input:         "at",
			outputSubstrs: []string{"msg=at"},
		},
		{
			name:         "under-level-debug",
			level:        hclog.Debug,
			input:        "under-debug",
			shouldNotLog: true,
		},
		{
			name:         "under-level-trace",
			level:        hclog.Trace,
			input:        "under-trace",
			shouldNotLog: true,
		},
		{
			name:         "plain-under-trace",
			plainLog:     true,
			level:        hclog.Trace,
			input:        "plain-under-trace",
			shouldNotLog: true,
		},
		{
			name:          "plain-at",
			plainLog:      true,
			level:         hclog.Info,
			input:         "plain-at",
			outputSubstrs: []string{"msg=plain-at"},
		},
		{
			name:          "plain-over-warn",
			plainLog:      true,
			level:         hclog.Warn,
			input:         "plain-over-warn",
			outputSubstrs: []string{"msg=plain-over-warn"},
		},
		{
			name:          "with-named",
			level:         hclog.Info,
			logOverride:   logger.Named("named-logger"),
			input:         "named-input",
			outputSubstrs: []string{"msg=named-input", "@original-log-name=named-logger"},
		},
		{
			name:          "sub-named",
			level:         hclog.Info,
			logOverride:   logger.Named("named-logger").Named("subnamed-logger"),
			input:         "subnamed-input",
			outputSubstrs: []string{"msg=subnamed-input", "@original-log-name=named-logger.subnamed-logger"},
		},
		{
			name:          "reset-named",
			level:         hclog.Info,
			logOverride:   logger.Named("named-logger").ResetNamed("reset-logger"),
			input:         "reset-input",
			outputSubstrs: []string{"msg=reset-input", "@original-log-name=reset-logger"},
		},
		{
			name:          "with-params",
			level:         hclog.Info,
			logOverride:   logger.With("with", "params"),
			input:         "with-params",
			outputSubstrs: []string{"msg=with-params", "with=params"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			buffer.Reset()
			loggerToUse := logger
			if tt.logOverride != nil {
				loggerToUse = tt.logOverride
			}

			switch tt.plainLog {
			case false:
				switch tt.level {
				case hclog.Error:
					assert.True(loggerToUse.IsError() == !tt.shouldNotLog)
					loggerToUse.Error(tt.input)
				case hclog.Warn:
					assert.True(loggerToUse.IsWarn() == !tt.shouldNotLog)
					loggerToUse.Warn(tt.input)
				case hclog.Info:
					assert.True(loggerToUse.IsInfo() == !tt.shouldNotLog)
					loggerToUse.Info(tt.input)
				case hclog.Debug:
					assert.True(loggerToUse.IsDebug() == !tt.shouldNotLog)
					loggerToUse.Debug(tt.input)
				case hclog.Trace:
					assert.True(loggerToUse.IsTrace() == !tt.shouldNotLog)
					loggerToUse.Trace(tt.input)
				}
			default:
				loggerToUse.Log(tt.level, tt.input)
			}

			switch tt.shouldNotLog {
			case true:
				assert.Len(buffer.String(), 0)
			default:
				for _, substr := range tt.outputSubstrs {
					assert.Contains(buffer.String(), substr)
				}
			}
		})
	}
}
