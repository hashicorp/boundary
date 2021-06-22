package event

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/eventlogger"
	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_InitSysEventer(t *testing.T) {
	// this test and its subtests cannot be run in parallel because of it's
	// dependency on the sysEventer
	testConfig := TestEventerConfig(t, "InitSysEventer")

	testEventer, err := NewEventer(hclog.Default(), testConfig.EventerConfig)
	require.NoError(t, err)

	tests := []struct {
		name      string
		log       hclog.Logger
		opt       []Option
		want      *Eventer
		wantErrIs error
	}{
		{
			name:      "missing-both-eventer-and-config",
			wantErrIs: ErrInvalidParameter,
		},
		{
			name:      "missing-hclog",
			opt:       []Option{WithEventerConfig(&testConfig.EventerConfig)},
			wantErrIs: ErrInvalidParameter,
		},
		{
			name: "success-with-config",
			opt:  []Option{WithEventerConfig(&testConfig.EventerConfig)},
			log:  hclog.Default(),
			want: &Eventer{
				logger: hclog.Default(),
				conf:   testConfig.EventerConfig,
			},
		},
		{
			name: "success-with-default-config",
			opt:  []Option{WithEventerConfig(&EventerConfig{})},
			log:  hclog.Default(),
			want: &Eventer{
				logger: hclog.Default(),
				conf: EventerConfig{
					Sinks: []SinkConfig{
						{
							Name:       "default",
							EventTypes: []Type{EveryType},
							Format:     JSONSinkFormat,
							SinkType:   StderrSink,
						},
					},
				},
			},
		},
		{
			name: "success-with-eventer",
			opt:  []Option{WithEventer(testEventer)},
			log:  hclog.Default(),
			want: testEventer,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer TestResetSystEventer(t)

			assert, require := assert.New(t), require.New(t)

			err := InitSysEventer(tt.log, tt.opt...)
			got := SysEventer()
			if tt.wantErrIs != nil {
				require.Nil(got)
				require.Error(err)
				assert.ErrorIs(err, tt.wantErrIs)
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
	ctx := context.Background()
	testSetup := TestEventerConfig(t, "TestEventer_writeObservation")
	eventer, err := NewEventer(hclog.Default(), testSetup.EventerConfig)
	require.NoError(t, err)

	testHeader := map[string]interface{}{"name": "header"}
	testDetail := map[string]interface{}{"name": "details"}
	testObservation, err := newObservation("Test_NewEventer", WithHeader(testHeader), WithDetails(testDetail))
	require.NoError(t, err)

	tests := []struct {
		name        string
		broker      broker
		observation *observation
		wantErrIs   error
	}{
		{
			name:      "missing-observation",
			broker:    &testMockBroker{},
			wantErrIs: ErrInvalidParameter,
		},
		{
			name:        "send-fails",
			broker:      &testMockBroker{errorOnSend: fmt.Errorf("%s: no msg: %w", "test", ErrIo)},
			observation: testObservation,
			wantErrIs:   ErrMaxRetries,
		},
		{
			name:        "success",
			broker:      &testMockBroker{},
			observation: testObservation,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			eventer.broker = tt.broker

			err = eventer.writeObservation(ctx, tt.observation)
			if tt.wantErrIs != nil {
				require.Error(err)
				assert.ErrorIs(err, tt.wantErrIs)
				return
			}
			require.NoError(err)
		})
	}
	t.Run("e2e", func(t *testing.T) {
		require := require.New(t)

		logger := hclog.New(&hclog.LoggerOptions{
			Name: "test",
		})
		c := EventerConfig{
			ObservationsEnabled: true,
		}
		// with no defined config, it will default to a stderr sink
		e, err := NewEventer(logger, c)
		require.NoError(err)

		m := map[string]interface{}{
			"name": "bar",
			"list": []string{"1", "2"},
		}
		observationEvent, err := newObservation("Test_NewEventer", WithHeader(m))
		require.NoError(err)

		require.NoError(e.writeObservation(context.Background(), observationEvent))
	})
}

func TestEventer_writeAudit(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	testSetup := TestEventerConfig(t, "Test_NewEventer")
	eventer, err := NewEventer(hclog.Default(), testSetup.EventerConfig)
	require.NoError(t, err)

	testAudit, err := newAudit(
		"TestEventer_writeAudit",
		WithRequestInfo(TestRequestInfo(t)),
		WithAuth(testAuth(t)),
		WithRequest(testRequest(t)),
		WithResponse(testResponse(t)))
	require.NoError(t, err)

	tests := []struct {
		name      string
		broker    broker
		audit     *audit
		wantErrIs error
	}{
		{
			name:      "missing-audit",
			broker:    &testMockBroker{},
			wantErrIs: ErrInvalidParameter,
		},
		{
			name:      "send-fails",
			broker:    &testMockBroker{errorOnSend: fmt.Errorf("%s: no msg: %w", "test", ErrIo)},
			audit:     testAudit,
			wantErrIs: ErrIo,
		},
		{
			name:   "success",
			broker: &testMockBroker{},
			audit:  testAudit,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			eventer.broker = tt.broker

			err = eventer.writeAudit(ctx, tt.audit)
			if tt.wantErrIs != nil {
				require.Error(err)
				assert.ErrorIs(err, tt.wantErrIs)
				return
			}
			require.NoError(err)
		})
	}
}

func TestEventer_writeError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	testSetup := TestEventerConfig(t, "Test_NewEventer")
	eventer, er := NewEventer(hclog.Default(), testSetup.EventerConfig)
	require.NoError(t, er)

	testError, er := newError("TestEventer_writeError", fmt.Errorf("%s: no msg: test", ErrIo))
	require.NoError(t, er)

	tests := []struct {
		name      string
		broker    broker
		err       *err
		wantErrIs error
	}{
		{
			name:      "missing-error",
			broker:    &testMockBroker{},
			wantErrIs: ErrInvalidParameter,
		},
		{
			name:      "send-fails",
			broker:    &testMockBroker{errorOnSend: fmt.Errorf("%s: no msg: test", ErrIo)},
			err:       testError,
			wantErrIs: ErrMaxRetries,
		},
		{
			name:   "success",
			broker: &testMockBroker{},
			err:    testError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			eventer.broker = tt.broker

			err := eventer.writeError(ctx, tt.err)
			if tt.wantErrIs != nil {
				require.Error(err)
				assert.ErrorIs(err, tt.wantErrIs)
				return
			}
			require.NoError(err)
		})
	}
}

func Test_NewEventer(t *testing.T) {
	t.Parallel()
	testSetup := TestEventerConfig(t, "Test_NewEventer")

	testSetupWithOpts := TestEventerConfig(t, "Test_NewEventer", testWithAuditSink(), testWithObservationSink())

	tests := []struct {
		name           string
		config         EventerConfig
		opts           []Option
		logger         hclog.Logger
		want           *Eventer
		wantRegistered []string
		wantPipelines  []string
		wantThresholds map[eventlogger.EventType]int
		wantErrIs      error
	}{
		{
			name:      "missing-logger",
			config:    testSetup.EventerConfig,
			wantErrIs: ErrInvalidParameter,
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
							SinkType:   StderrSink,
						},
					},
				},
			},
			wantRegistered: []string{
				"json",              // fmt for everything
				"stderr",            // stderr
				"gated-observation", // stderr
				"gated-audit",       // stderr
			},
			wantPipelines: []string{
				"audit",       // stderr
				"observation", // stderr
				"error",       // stderr
			},
			wantThresholds: map[eventlogger.EventType]int{
				"error": 1,
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
			wantRegistered: []string{
				"json",              // fmt for everything
				"stderr",            // stderr
				"gated-observation", // stderr
				"gated-audit",       // stderr
				"tmp-all-events",    // every-type-file-sync
				"gated-observation", // every-type-file-sync
				"gated-audit",       // every-type-file-sync
				"tmp-errors",        // error-file-sink
			},
			wantPipelines: []string{
				"audit",       // every-type-file-sync
				"audit",       // stderr
				"observation", // every-type-file-sync
				"observation", // stderr
				"error",       // every-type-file-sync
				"error",       // stderr
				"error",       // error-file-sink
			},
			wantThresholds: map[eventlogger.EventType]int{
				"error": 3,
			},
		},
		{
			name:   "testSetup-with-all-opts",
			config: testSetupWithOpts.EventerConfig,
			logger: hclog.Default(),
			want: &Eventer{
				logger: hclog.Default(),
				conf:   testSetupWithOpts.EventerConfig,
			},
			wantRegistered: []string{
				"json",              // fmt for everything
				"stderr",            // stderr
				"gated-observation", // stderr
				"gated-audit",       // stderr
				"tmp-all-events",    // every-type-file-sync
				"gated-observation", // every-type-file-sync
				"gated-audit",       // every-type-file-sync
				"tmp-errors",        // error-file-sink
				"gated-observation", // observation-file-sink
				"tmp-observation",   // observations-file-sink
				"gated-audit",       // audit-file-sink
				"tmp-audit",         // audit-file-sink
			},
			wantPipelines: []string{
				"audit",       // every-type-file-sync
				"audit",       // stderr
				"observation", // every-type-file-sync
				"observation", // stderr
				"error",       // every-type-file-sync
				"error",       // stderr
				"error",       // error-file-sink
				"audit",       // audit-file-sink
				"observation", // observation-file-sink
			},
			wantThresholds: map[eventlogger.EventType]int{
				"error": 3,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			testBroker := &testMockBroker{}
			got, err := NewEventer(tt.logger, tt.config, testWithBroker(testBroker))
			if tt.wantErrIs != nil {
				require.Error(err)
				require.Nil(got)
				assert.ErrorIs(err, tt.wantErrIs)
				return
			}
			require.NoError(err)
			require.NotNil(got)
			tt.want.broker = got.broker
			tt.want.flushableNodes = got.flushableNodes
			assert.Equal(tt.want, got)

			assert.Lenf(testBroker.registeredNodeIds, len(tt.wantRegistered), "got nodes: %q", testBroker.registeredNodeIds)
			for _, want := range tt.wantRegistered {
				found := false
				for _, got := range testBroker.registeredNodeIds {
					if strings.Contains(string(got), want) {
						found = true
						break
					}
				}
				assert.Truef(found, "did not find %s in the registered nodes: %s", want, testBroker.registeredNodeIds)
			}
			assert.Lenf(testBroker.pipelines, len(tt.wantPipelines), "got pipelines: %q", testBroker.pipelines)
			for _, want := range tt.wantPipelines {
				found := false
				for _, got := range testBroker.pipelines {
					if strings.Contains(string(got.EventType), want) {
						found = true
						break
					}
				}
				assert.Truef(found, "did not find %s in the registered pipelines: %s", want, testBroker.pipelines)
			}

			assert.Equal(tt.wantThresholds, testBroker.successThresholds)
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

		e.broker = &testMockBroker{}
		require.NoError(e.Reopen())
		assert.True(e.broker.(*testMockBroker).reopened)
	})
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
		return fmt.Errorf("%s: test error: flush-all", ErrInvalidParameter)
	}
	return nil
}
