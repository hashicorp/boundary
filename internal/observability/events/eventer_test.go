package event

import (
	"context"
	"os"
	"testing"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/eventlogger"
	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_InitSysEventer(t *testing.T) {
	// this test and its subtests cannot be run in parallel because of it's
	// dependency on the sysEventer
	testConfig := TestEventerConfig(t, "InitSysEventer")
	defer os.Remove(testConfig.AllEvents.Name())   // just to be sure it's gone after all the tests are done.
	defer os.Remove(testConfig.ErrorEvents.Name()) // just to be sure it's gone after all the tests are done.

	tests := []struct {
		name         string
		log          hclog.Logger
		config       EventerConfig
		want         *Eventer
		wantErrMatch *errors.Template
	}{

		{
			name:         "missing-hclog",
			config:       testConfig.EventerConfig,
			wantErrMatch: errors.T(errors.InvalidParameter),
		},
		{
			name:   "success",
			config: testConfig.EventerConfig,
			log:    hclog.Default(),
			want: &Eventer{
				logger: hclog.Default(),
				conf:   testConfig.EventerConfig,
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

func TestEventer_writeObservation(t *testing.T) {
	t.Parallel()
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

// TODO -> jimlambrt: we need to complete this set of unit tests with coverage
// for all the configuration possibilities.
func Test_NewEventer(t *testing.T) {
	t.Parallel()
	testSetup := TestEventerConfig(t, "Test_NewEventer")
	defer os.Remove(testSetup.AllEvents.Name())
	defer os.Remove(testSetup.ErrorEvents.Name())

	tests := []struct {
		name         string
		config       EventerConfig
		logger       hclog.Logger
		want         *Eventer
		wantErrMatch *errors.Template
	}{
		{
			name:         "missing logger",
			config:       testSetup.EventerConfig,
			wantErrMatch: errors.T(errors.InvalidParameter),
		},
		{
			name:   "success-with-default-config",
			config: EventerConfig{},
			logger: hclog.Default(),
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
		{
			name:   "testSetup",
			config: testSetup.EventerConfig,
			logger: hclog.Default(),
			want: &Eventer{
				logger: hclog.Default(),
				conf:   testSetup.EventerConfig,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := NewEventer(tt.logger, tt.config)
			if tt.wantErrMatch != nil {
				require.Error(err)
				require.Nil(got)
				assert.True(errors.Match(tt.wantErrMatch, err))
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

func TestEventer_Reopen(t *testing.T) {
	t.Parallel()
	t.Run("simple", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)

		e, err := NewEventer(hclog.Default(), EventerConfig{})
		require.NoError(err)

		e.broker = nil
		require.NoError(e.Reopen())

		e.broker = &testReopenBroker{}
		require.NoError(e.Reopen())
		assert.True(e.broker.(*testReopenBroker).reopened)
	})
}

type testReopenBroker struct {
	reopened bool
}

func (b *testReopenBroker) Reopen(ctx context.Context) error {
	b.reopened = true
	return nil
}

func (b *testReopenBroker) Send(ctx context.Context, t eventlogger.EventType, payload interface{}) (eventlogger.Status, error) {
	return eventlogger.Status{}, nil
}

func TestEventer_FlushNodes(t *testing.T) {
	t.Parallel()
	t.Run("simple", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)

		e, err := NewEventer(hclog.Default(), EventerConfig{})
		require.NoError(err)

		node := &testFlushNode{}
		e.flushableNodes = append(e.flushableNodes, node)
		require.NoError(e.FlushNodes(context.Background()))

		node.raiseError = true
		require.Error(e.FlushNodes(context.Background()))

		assert.True(node.flushed)
	})
}

type testFlushNode struct {
	flushed    bool
	raiseError bool
}

func (t *testFlushNode) FlushAll(_ context.Context) error {
	t.flushed = true
	if t.raiseError {
		return errors.New(errors.InvalidParameter, "flush-all", "test error")
	}
	return nil
}
