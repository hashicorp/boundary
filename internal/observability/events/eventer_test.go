package event

import (
	"context"
	"io/ioutil"
	"os"
	"testing"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_InitSysEventer(t *testing.T) {
	// this test and its subtests cannot be run in parallel because of it's
	// dependency on the sysEventer

	tmpFile, err := ioutil.TempFile("./", "test_writeobservation-observation")
	require.NoError(t, err)
	tmpFile.Close()
	defer os.Remove(tmpFile.Name()) // just to be sure it's gone after all the tests are done.

	tmpErrFile, err := ioutil.TempFile("./", "test-init-sys-eventer-err")
	require.NoError(t, err)
	tmpErrFile.Close()
	defer os.Remove(tmpErrFile.Name()) // just to be sure it's gone after all the tests are done.

	testConfig := EventerConfig{
		ObservationsEnabled: true,
		ObservationDelivery: Enforced,
		Sinks: []SinkConfig{
			{
				Name:       "observation-file-sink",
				EventTypes: []Type{EveryType},
				Format:     JSONSinkFormat,
				Path:       "./",
				FileName:   tmpFile.Name(),
			},
			{
				Name:       "stdout",
				EventTypes: []Type{EveryType},
				Format:     JSONSinkFormat,
				SinkType:   StdoutSink,
			},
			{
				Name:       "err-file-sink",
				EventTypes: []Type{ErrorType},
				Format:     JSONSinkFormat,
				Path:       "./",
				FileName:   tmpErrFile.Name(),
			},
		},
	}

	tests := []struct {
		name         string
		log          hclog.Logger
		config       EventerConfig
		want         *Eventer
		wantErrMatch *errors.Template
	}{

		{
			name:         "missing-hclog",
			config:       testConfig,
			wantErrMatch: errors.T(errors.InvalidParameter),
		},
		{
			name:   "success",
			config: testConfig,
			log:    hclog.Default(),
			want: &Eventer{
				logger: hclog.Default(),
				conf:   testConfig,
			},
		},
		{
			name:   "success-with-default-config",
			config: EventerConfig{},
			log:    hclog.Default(),
			want: &Eventer{
				logger: hclog.Default(),
				conf: EventerConfig{
					Sinks: []SinkConfig{
						{
							Name:       "default",
							EventTypes: []Type{EveryType},
							Format:     JSONSinkFormat,
							SinkType:   StdoutSink,
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer testResetSystEventer(t)

			assert, require := assert.New(t), require.New(t)

			err := InitSysEventer(tt.log, tt.config)
			got := SysEventer()
			if tt.wantErrMatch != nil {
				require.Nil(got)
				require.Error(err)
				if tt.wantErrMatch != nil {
					assert.True(errors.Match(tt.wantErrMatch, err))
				}
				return
			}
			require.NoError(err)
			require.NotNil(got)
			tt.want.broker = got.broker
			tt.want.flushableNodes = got.flushableNodes
			assert.Equal(tt.want, got)
		})
	}
}

func Test_NewEventer(t *testing.T) {
	require := require.New(t)

	logger := hclog.New(&hclog.LoggerOptions{
		Name: "test",
	})
	c := EventerConfig{
		ObservationsEnabled: true,
	}
	// with no defined config, it will default to a stdout sink
	e, err := NewEventer(logger, c)
	require.NoError(err)

	m := map[string]interface{}{
		"name": "bar",
		"list": []string{"1", "2"},
	}
	observationEvent, err := newObservation("Test_NewEventer", WithHeader(m))
	require.NoError(err)

	require.NoError(e.writeObservation(context.Background(), observationEvent))

}
