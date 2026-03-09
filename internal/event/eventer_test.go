// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package event

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/hashicorp/eventlogger"
	"github.com/hashicorp/eventlogger/filters/encrypt"
	"github.com/hashicorp/eventlogger/formatter_filters/cloudevents"
	"github.com/hashicorp/go-hclog"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_InitSysEventer(t *testing.T) {
	// this test and its subtests cannot be run in parallel because of it's
	// dependency on the sysEventer
	testConfig := TestEventerConfig(t, "InitSysEventer")
	testLock := &sync.Mutex{}
	testLogger := hclog.New(&hclog.LoggerOptions{
		Mutex:      testLock,
		JSONFormat: true,
	})
	testEventer, err := NewEventer(testLogger, testLock, "Test_InitSysEventer", testConfig.EventerConfig)
	require.NoError(t, err)

	tests := []struct {
		name       string
		log        hclog.Logger
		lock       *sync.Mutex
		serverName string
		opt        []Option
		want       *Eventer
		wantErrIs  error
	}{
		{
			name:       "missing-both-eventer-and-config",
			serverName: "missing-both-eventer-and-config",
			wantErrIs:  ErrInvalidParameter,
		},
		{
			name:       "missing-hclog",
			opt:        []Option{WithEventerConfig(&testConfig.EventerConfig)},
			lock:       testLock,
			serverName: "missing-hclog",
			wantErrIs:  ErrInvalidParameter,
		},
		{
			name:       "missing-lock",
			opt:        []Option{WithEventerConfig(&testConfig.EventerConfig)},
			log:        testLogger,
			serverName: "missing-lock",
			wantErrIs:  ErrInvalidParameter,
		},
		{
			name:      "missing-serverName",
			opt:       []Option{WithEventerConfig(&testConfig.EventerConfig)},
			log:       testLogger,
			lock:      testLock,
			wantErrIs: ErrInvalidParameter,
		},
		{
			name:       "missing-eventer-and-config",
			log:        testLogger,
			lock:       testLock,
			serverName: "success-with-config",
			wantErrIs:  ErrInvalidParameter,
		},
		{
			name:       "both-eventer-and-config",
			opt:        []Option{WithEventerConfig(&testConfig.EventerConfig), WithEventer(testEventer)},
			log:        testLogger,
			lock:       testLock,
			serverName: "success-with-config",
			wantErrIs:  ErrInvalidParameter,
		},
		{
			name:       "bad-config",
			opt:        []Option{WithEventerConfig(&EventerConfig{Sinks: []*SinkConfig{{Format: "bad-format"}}})},
			log:        testLogger,
			lock:       testLock,
			serverName: "success-with-config",
			wantErrIs:  ErrInvalidParameter,
		},
		{
			name:       "success-with-config",
			opt:        []Option{WithEventerConfig(&testConfig.EventerConfig)},
			log:        testLogger,
			lock:       testLock,
			serverName: "success-with-config",
			want: &Eventer{
				logger:         testLogger,
				gatedQueueLock: new(sync.Mutex),
				conf:           testConfig.EventerConfig,
			},
		},
		{
			name:       "success-with-default-config",
			opt:        []Option{WithEventerConfig(&EventerConfig{})},
			log:        testLogger,
			lock:       testLock,
			serverName: "success-with-default-config",
			want: &Eventer{
				logger:         testLogger,
				gatedQueueLock: new(sync.Mutex),
				conf: EventerConfig{
					Sinks: []*SinkConfig{
						{
							Name:        "default",
							EventTypes:  []Type{EveryType},
							Format:      JSONSinkFormat,
							Type:        StderrSink,
							AuditConfig: DefaultAuditConfig(),
						},
					},
				},
			},
		},
		{
			name:       "success-with-eventer",
			opt:        []Option{WithEventer(testEventer)},
			log:        testLogger,
			lock:       testLock,
			serverName: "success-with-eventer",
			want:       testEventer,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer TestResetSystEventer(t)

			assert, require := assert.New(t), require.New(t)
			err := InitSysEventer(tt.log, tt.lock, tt.serverName, tt.opt...)
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
			tt.want.auditPipelines = got.auditPipelines
			tt.want.errPipelines = got.errPipelines
			tt.want.observationPipelines = got.observationPipelines
			tt.want.auditWrapperNodes = got.auditWrapperNodes
			tt.want.serverName = got.serverName
			assert.Equal(tt.want, got)
		})
	}
}

func TestEventer_writeObservation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	testSetup := TestEventerConfig(t, "TestEventer_writeObservation")
	testLock := &sync.Mutex{}
	testLogger := testLogger(t, testLock)

	eventer, err := NewEventer(testLogger, testLock, "TestEventer_writeObservation", testSetup.EventerConfig)
	require.NoError(t, err)

	testHeader := map[string]any{"name": "header"}
	testDetail := map[string]any{"name": "details"}
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

		c := EventerConfig{
			ObservationsEnabled: true,
		}

		// with no defined config, it will default to a stderr sink
		e, err := NewEventer(testLogger, testLock, "e2e-test", c)
		require.NoError(err)

		m := map[string]any{
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
	testLock := &sync.Mutex{}
	testLogger := testLogger(t, testLock)
	eventer, err := NewEventer(testLogger, testLock, "TestEventer_writeAudit", testSetup.EventerConfig)
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
	testLock := &sync.Mutex{}
	testLogger := testLogger(t, testLock)

	eventer, er := NewEventer(testLogger, testLock, "TestEventer_writeError", testSetup.EventerConfig)
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
	testSetup := TestEventerConfig(t, "Test_NewEventer", TestWithStderrSink(t))

	testSetupWithOpts := TestEventerConfig(t, "Test_NewEventer", TestWithStderrSink(t), TestWithAuditSink(t), TestWithObservationSink(t), TestWithSysSink(t))

	testHclogSetup := TestEventerConfig(t, "Test_NewEventer", TestWithStderrSink(t), testWithSinkFormat(t, TextHclogSinkFormat))

	testLock := &sync.Mutex{}
	testLogger := testLogger(t, testLock)

	twrapper := testWrapper(t)

	tests := []struct {
		name            string
		config          EventerConfig
		opts            []Option
		logger          hclog.Logger
		lock            *sync.Mutex
		serverName      string
		want            *Eventer
		wantRegistered  []string
		wantPipelines   []string
		wantThresholds  map[eventlogger.EventType]int
		wantErrIs       error
		wantErrContains string
	}{
		{
			name: "valid-audit-configr",
			config: func() EventerConfig {
				cfg := EventerConfig{
					AuditEnabled: true,
					Sinks: []*SinkConfig{
						{
							Name:       "test",
							EventTypes: []Type{AuditType},
							Type:       StderrSink,
							Format:     JSONSinkFormat,
							AuditConfig: &AuditConfig{
								FilterOverrides: AuditFilterOperations{
									SensitiveClassification: EncryptOperation,
								},
							},
						},
					},
				}
				return cfg
			}(),
			opts:       []Option{WithAuditWrapper(twrapper)},
			lock:       testLock,
			logger:     testLogger,
			serverName: "valid-audit-config",
			want: &Eventer{
				logger:         testLogger,
				gatedQueueLock: new(sync.Mutex),
				conf: EventerConfig{
					AuditEnabled: true,
					Sinks: []*SinkConfig{
						{
							Name:       "test",
							EventTypes: []Type{AuditType},
							Format:     JSONSinkFormat,
							Type:       StderrSink,
							AuditConfig: &AuditConfig{
								wrapper: twrapper,
								FilterOverrides: AuditFilterOperations{
									SensitiveClassification: EncryptOperation,
								},
							},
						},
					},
				},
			},
			wantRegistered: []string{
				"cloudevents",   // fmt for everything
				"stderr",        // stderr
				"gated-audit",   // stderr
				"encrypt-audit", // stderr
			},
			wantPipelines: []string{
				"audit", // stderr
			},
			wantThresholds: map[eventlogger.EventType]int{
				"error":       0,
				"system":      0,
				"observation": 0,
				"audit":       1,
			},
		},
		{
			name:       "missing-logger",
			config:     testSetup.EventerConfig,
			lock:       testLock,
			serverName: "missing-logger",
			wantErrIs:  ErrInvalidParameter,
		},
		{
			name:       "missing-lock",
			config:     testSetup.EventerConfig,
			logger:     testLogger,
			serverName: "missing-lock",
			wantErrIs:  ErrInvalidParameter,
		},
		{
			name:      "missing-server-name",
			config:    testSetup.EventerConfig,
			logger:    testLogger,
			lock:      testLock,
			wantErrIs: ErrInvalidParameter,
		},
		{
			name: "dup-sink-filename",
			config: func() EventerConfig {
				dupFileConfig := TestEventerConfig(t, "dup-sink-filename")
				dupFileConfig.EventerConfig.Sinks = append(dupFileConfig.EventerConfig.Sinks,
					&SinkConfig{
						Name:       "err-file-sink",
						Type:       FileSink,
						EventTypes: []Type{ErrorType},
						Format:     JSONSinkFormat,
						FileConfig: &FileSinkTypeConfig{
							Path:     "./",
							FileName: dupFileConfig.ErrorEvents.Name(),
						},
					},
				)
				return dupFileConfig.EventerConfig
			}(),
			logger:     testLogger,
			lock:       testLock,
			serverName: "dup-sink-filename",
			wantErrIs:  ErrInvalidParameter,
		},
		{
			name:       "success-with-default-config",
			config:     EventerConfig{},
			logger:     testLogger,
			lock:       testLock,
			serverName: "success-with-default-config",
			want: &Eventer{
				logger:         testLogger,
				gatedQueueLock: new(sync.Mutex),
				conf: EventerConfig{
					Sinks: []*SinkConfig{
						{
							Name:        "default",
							EventTypes:  []Type{EveryType},
							Format:      JSONSinkFormat,
							Type:        StderrSink,
							AuditConfig: DefaultAuditConfig(),
						},
					},
				},
			},
			wantRegistered: []string{
				"cloudevents",       // fmt for everything
				"stderr",            // stderr
				"gated-observation", // stderr
				"gated-audit",       // stderr
				"encrypt-audit",     // stderr
			},
			wantPipelines: []string{
				"audit",       // stderr
				"observation", // stderr
				"error",       // stderr
				"system",      // stderr
			},
			wantThresholds: map[eventlogger.EventType]int{
				"error":       1,
				"system":      1,
				"observation": 1,
				"audit":       1,
			},
		},
		{
			name:       "testSetup",
			config:     testSetup.EventerConfig,
			logger:     testLogger,
			lock:       testLock,
			serverName: "testSetup",
			want: &Eventer{
				logger:         testLogger,
				gatedQueueLock: new(sync.Mutex),
				conf:           testSetup.EventerConfig,
			},
			wantRegistered: []string{
				"cloudevents",       // stderr
				"stderr",            // stderr
				"gated-observation", // stderr
				"gated-audit",       // stderr
				"encrypt-audit",     // stderr
				"cloudevents",       // every-type-file-sync
				"tmp-all-events",    // every-type-file-sync
				"gated-observation", // every-type-file-sync
				"gated-audit",       // every-type-file-sync
				"encrypt-audit",     // every-type-file-sync
				"cloudevents",       // error-file-sink
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
				"system",      // stderr
				"system",      // stderr
			},
			wantThresholds: map[eventlogger.EventType]int{
				"error":       3,
				"system":      2,
				"observation": 2,
				"audit":       2,
			},
		},
		{
			name:       "testSetup-with-all-opts",
			config:     testSetupWithOpts.EventerConfig,
			logger:     testLogger,
			lock:       testLock,
			serverName: "testSetup-with-all-opts",
			want: &Eventer{
				logger:         testLogger,
				gatedQueueLock: new(sync.Mutex),
				conf:           testSetupWithOpts.EventerConfig,
			},
			wantRegistered: []string{
				"cloudevents",       // stderr
				"stderr",            // stderr
				"gated-observation", // stderr
				"gated-audit",       // stderr
				"encrypt-audit",     // stderr
				"cloudevents",       // every-type-file-sync
				"tmp-all-events",    // every-type-file-sync
				"gated-observation", // every-type-file-sync
				"gated-audit",       // every-type-file-sync
				"encrypt-audit",     // every-type-file-sync
				"cloudevents",       // error-file-sink
				"tmp-errors",        // error-file-sink
				"cloudevents",       // observation-file-sink
				"gated-observation", // observation-file-sink
				"tmp-observation",   // observations-file-sink
				"cloudevents",       // audit-file-sink
				"gated-audit",       // audit-file-sink
				"encrypt-audit",     // audit-file-sink
				"tmp-audit",         // audit-file-sink
				"cloudevents",       // sys-file-sink
				"tmp-sysevents",     // sys-file-sink
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
				"system",      // stderr
				"system",      // every-type-file-sync
				"system",      // sys-file-sink
			},
			wantThresholds: map[eventlogger.EventType]int{
				"error":       3,
				"system":      3,
				"observation": 3,
				"audit":       3,
			},
		},
		{
			name:       "testSetup-with-hclog",
			config:     testHclogSetup.EventerConfig,
			logger:     testLogger,
			lock:       testLock,
			serverName: "testSetup",
			want: &Eventer{
				logger:         testLogger,
				gatedQueueLock: new(sync.Mutex),
				conf:           testHclogSetup.EventerConfig,
			},
			wantRegistered: []string{
				"hclog-text",        // stderr
				"stderr",            // stderr
				"gated-observation", // stderr
				"gated-audit",       // stderr
				"encrypt-audit",     // stderr
				"hclog-text",        // every-type-file-sync
				"tmp-all-events",    // every-type-file-sync
				"gated-observation", // every-type-file-sync
				"gated-audit",       // every-type-file-sync
				"encrypt-audit",     // every-type-file-sync
				"hclog-text",        // error-file-sink
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
				"system",      // stderr
				"system",      // stderr
			},
			wantThresholds: map[eventlogger.EventType]int{
				"error":       3,
				"system":      2,
				"observation": 2,
				"audit":       2,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			testBroker := &testMockBroker{}
			opts := []Option{TestWithBroker(t, testBroker)}
			if tt.opts != nil {
				opts = append(opts, tt.opts...)
			}
			got, err := NewEventer(tt.logger, tt.lock, tt.serverName, tt.config, opts...)
			if tt.wantErrIs != nil {
				require.Error(err)
				require.Nil(got)
				assert.ErrorIs(err, tt.wantErrIs)
				if tt.wantErrContains != "" {
					assert.Contains(err.Error(), tt.wantErrContains)
				}
				return
			}
			require.NoError(err)
			require.NotNil(got)
			tt.want.broker = got.broker
			tt.want.flushableNodes = got.flushableNodes
			tt.want.auditPipelines = got.auditPipelines
			tt.want.errPipelines = got.errPipelines
			tt.want.observationPipelines = got.observationPipelines
			tt.want.auditWrapperNodes = got.auditWrapperNodes
			tt.want.serverName = got.serverName
			assert.Equal(tt.want, got)

			assert.Lenf(testBroker.registeredNodeIds, len(tt.wantRegistered), "got nodes: %q", testBroker.registeredNodeIds)
			registeredNodeIds := map[string]bool{}
			for _, id := range testBroker.registeredNodeIds {
				registeredNodeIds[string(id)] = true
			}
			for _, want := range tt.wantRegistered {
				found := false
				for got := range registeredNodeIds {
					if strings.Contains(got, want) {
						found = true
						delete(registeredNodeIds, got)
						break
					}
				}
				assert.Truef(found, "did not find %s in the registered nodes: %s", want, testBroker.registeredNodeIds)
			}

			assert.Lenf(testBroker.pipelines, len(tt.wantPipelines), "got pipelines: %q", testBroker.pipelines)
			registeredPipelines := map[string]eventlogger.Pipeline{}
			gotAuditCnt := 0
			gotErrCnt := 0
			gotObservationCnt := 0
			for _, got := range testBroker.pipelines {
				registeredPipelines[string(got.PipelineID)] = got
				switch got.EventType {
				case eventlogger.EventType(AuditType):
					gotAuditCnt += 1
				case eventlogger.EventType(ErrorType):
					gotErrCnt += 1
				case eventlogger.EventType(ObservationType):
					gotObservationCnt += 1
				}
			}
			wantAuditCnt := 0
			wantErrCnt := 0
			wantObservationCnt := 0
			for _, want := range tt.wantPipelines {
				switch want {
				case string(AuditType):
					wantAuditCnt += 1
				case string(ErrorType):
					wantErrCnt += 1
				case string(ObservationType):
					wantObservationCnt += 1
				}
				found := false
				for id, got := range registeredPipelines {
					if strings.Contains(string(got.EventType), want) {
						found = true
						delete(registeredPipelines, id)
						break
					}
				}
				assert.Truef(found, "did not find %s in the registered pipelines: %s", want, testBroker.pipelines)
			}
			assert.Equal(wantAuditCnt, gotAuditCnt)
			assert.Equal(wantErrCnt, gotErrCnt)
			assert.Equal(wantObservationCnt, gotObservationCnt)

			assert.Equal(tt.wantThresholds, testBroker.successThresholds)
		})
	}
}

func TestEventer_Reopen(t *testing.T) {
	t.Parallel()
	t.Run("simple", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)

		testLock := &sync.Mutex{}
		testLogger := testLogger(t, testLock)

		e, err := NewEventer(testLogger, testLock, "TestEventer_Reopen", EventerConfig{})
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
		testLock := &sync.Mutex{}
		testLogger := testLogger(t, testLock)

		e, err := NewEventer(testLogger, testLock, "TestEventer_FlushNodes", EventerConfig{})
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

func Test_StandardLogger(t *testing.T) {
	// this test and its subtests cannot be run in parallel because of it's
	// dependency on the sysEventer

	testCtx := context.Background()
	c := TestEventerConfig(t, "Test_StandardLogger")
	testLock := &sync.Mutex{}
	testLogger := testLogger(t, testLock)

	require.NoError(t, InitSysEventer(testLogger, testLock, "Test_StandardLogger", WithEventerConfig(&c.EventerConfig)))

	tests := []struct {
		name            string
		eventer         *Eventer
		ctx             context.Context
		eventType       Type
		wantErr         bool
		wantErrIs       error
		wantErrContains string
	}{
		{
			name:            "missing-eventer",
			ctx:             testCtx,
			eventType:       ErrorType,
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "nil eventer",
		},
		{
			name:            "missing-ctx",
			eventer:         SysEventer(),
			eventType:       ErrorType,
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing context",
		},
		{
			name:            "missing-type",
			ctx:             testCtx,
			eventer:         SysEventer(),
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing type",
		},
		{
			name:            "invalid-type",
			ctx:             testCtx,
			eventer:         SysEventer(),
			eventType:       "invalid",
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "'invalid' is not a valid event type",
		},
		{
			name:      "okay",
			ctx:       testCtx,
			eventer:   SysEventer(),
			eventType: ErrorType,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			e := SysEventer()
			require.NotNil(e)
			l, err := tt.eventer.StandardLogger(tt.ctx, tt.name, tt.eventType)
			if tt.wantErr {
				require.Error(err)
				assert.Nil(l)
				if tt.wantErrIs != nil {
					assert.ErrorIs(err, tt.wantErrIs)
				}
				if tt.wantErrContains != "" {
					assert.Contains(err.Error(), tt.wantErrContains)
				}
				return
			}
			require.NoError(err)
			assert.NotNil(l)
		})
	}
}

func Test_StandardWriter(t *testing.T) {
	// this test and its subtests cannot be run in parallel because of it's
	// dependency on the sysEventer

	c := TestEventerConfig(t, "Test_StandardLogger")
	testLock := &sync.Mutex{}
	testLogger := testLogger(t, testLock)

	require.NoError(t, InitSysEventer(testLogger, testLock, "Test_StandardLogger", WithEventerConfig(&c.EventerConfig)))

	testCtx, err := NewEventerContext(context.Background(), SysEventer())
	require.NoError(t, err)

	tests := []struct {
		name            string
		eventer         *Eventer
		ctx             context.Context
		eventType       Type
		wantErr         bool
		wantErrIs       error
		wantErrContains string
		wantWriter      io.Writer
	}{
		{
			name:            "missing-eventer",
			ctx:             testCtx,
			eventType:       ErrorType,
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "nil eventer",
		},
		{
			name:            "missing-ctx",
			eventer:         SysEventer(),
			eventType:       ErrorType,
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing context",
		},
		{
			name:            "missing-type",
			ctx:             testCtx,
			eventer:         SysEventer(),
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing type",
		},
		{
			name:            "invalid-type",
			ctx:             testCtx,
			eventer:         SysEventer(),
			eventType:       "invalid",
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "'invalid' is not a valid event type",
		},
		{
			name:      "okay",
			ctx:       context.Background(),
			eventer:   SysEventer(),
			eventType: ErrorType,
			wantWriter: &logAdapter{
				ctxWithEventer: testCtx,
				e:              SysEventer(),
				emitEventType:  ErrorType,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			e := SysEventer()
			require.NotNil(e)
			l, err := tt.eventer.StandardWriter(tt.ctx, tt.eventType)
			if tt.wantErr {
				require.Error(err)
				assert.Nil(l)
				if tt.wantErrIs != nil {
					assert.ErrorIs(err, tt.wantErrIs)
				}
				if tt.wantErrContains != "" {
					assert.Contains(err.Error(), tt.wantErrContains)
				}
				return
			}
			require.NoError(err)
			assert.NotNil(l)
			assert.Equal(tt.wantWriter, l)
		})
	}
}

func Test_logAdapter_Write(t *testing.T) {
	// this test and its subtests cannot be run in parallel because of it's
	// dependency on the sysEventer

	c := TestEventerConfig(t, "Test_StandardLogger")
	testLock := &sync.Mutex{}
	testLogger := testLogger(t, testLock)

	require.NoError(t, InitSysEventer(testLogger, testLock, "Test_StandardLogger", WithEventerConfig(&c.EventerConfig)))

	testCtx, err := NewEventerContext(context.Background(), SysEventer())
	require.NoError(t, err)

	tests := []struct {
		name            string
		adapter         *logAdapter
		data            []byte
		wantErr         bool
		wantIsError     error
		wantErrContains string
		wantErrorEvent  string
		wantSystemEvent string
	}{
		{
			name:            "nil-adapter",
			data:            []byte("nil-adapter"),
			wantErr:         true,
			wantIsError:     ErrInvalidParameter,
			wantErrContains: "nil log adapter",
		},
		{
			name: "emit-sys-event",
			adapter: &logAdapter{
				ctxWithEventer: testCtx,
				e:              SysEventer(),
				emitEventType:  SystemType,
			},
			data:            []byte("emit-sys-event"),
			wantSystemEvent: "emit-sys-event",
		},
		{
			name: "pick-type-DEBUG",
			adapter: &logAdapter{
				ctxWithEventer: testCtx,
				e:              SysEventer(),
			},
			data:            []byte("[DEBUG] pick-type-DEBUG"),
			wantSystemEvent: "pick-type-DEBUG",
		},
		{
			name: "pick-type-TRACE",
			adapter: &logAdapter{
				ctxWithEventer: testCtx,
				e:              SysEventer(),
			},
			data:            []byte("[TRACE] pick-type-TRACE"),
			wantSystemEvent: "pick-type-TRACE",
		},
		{
			name: "pick-type-INFO",
			adapter: &logAdapter{
				ctxWithEventer: testCtx,
				e:              SysEventer(),
			},
			data:            []byte("[INFO] pick-type-INFO"),
			wantSystemEvent: "pick-type-INFO",
		},
		{
			name: "pick-type-WARN",
			adapter: &logAdapter{
				ctxWithEventer: testCtx,
				e:              SysEventer(),
			},
			data:            []byte("[WARN] pick-type-WARN"),
			wantSystemEvent: "pick-type-WARN",
		},
		{
			name: "emit-error-event",
			adapter: &logAdapter{
				ctxWithEventer: testCtx,
				e:              SysEventer(),
				emitEventType:  ErrorType,
			},
			data:           []byte("emit-error-event"),
			wantErrorEvent: "emit-error-event",
		},
		{
			name: "pick-type-ERR",
			adapter: &logAdapter{
				ctxWithEventer: testCtx,
				e:              SysEventer(),
			},
			data:           []byte("[ERR] pick-type-ERR"),
			wantErrorEvent: "pick-type-ERR",
		},
		{
			name: "pick-type-ERROR",
			adapter: &logAdapter{
				ctxWithEventer: testCtx,
				e:              SysEventer(),
			},
			data:           []byte("[ERROR] pick-type-ERROR"),
			wantErrorEvent: "pick-type-ERROR",
		},
		{
			name: "emit-every-type-event",
			adapter: &logAdapter{
				ctxWithEventer: testCtx,
				e:              SysEventer(),
				emitEventType:  EveryType,
			},
			data:            []byte("emit-every-type-event"),
			wantSystemEvent: "emit-every-type-event",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			i, err := tt.adapter.Write(tt.data)
			if tt.wantErr {
				require.Error(err)
				assert.Zero(i)
				if tt.wantIsError != nil {
					assert.ErrorIs(err, tt.wantIsError)
				}
				if tt.wantErrContains != "" {
					assert.Contains(err.Error(), tt.wantErrContains)
				}
				return
			}
			require.NoError(err)
			assert.Equal(len(tt.data), i)

			sinkFileName := c.AllEvents.Name()
			defer func() { _ = os.WriteFile(sinkFileName, nil, 0o666) }()
			b, err := os.ReadFile(sinkFileName)
			require.NoError(err)
			gotEvent := &cloudevents.Event{}
			err = json.Unmarshal(b, gotEvent)
			require.NoErrorf(err, "json: %s", string(b))

			if tt.wantErrorEvent != "" {
				gotData := gotEvent.Data.(map[string]any)
				t.Log(tt.name, gotData)
				assert.Equal(tt.wantErrorEvent, gotData["error"])
			}
			if tt.wantSystemEvent != "" {
				gotData := gotEvent.Data.(map[string]any)["data"].(map[string]any)
				t.Log(tt.name, gotData)
				assert.Equal(tt.wantSystemEvent, gotData["msg"])
			}
		})
	}
}

func TestEventer_RotateAuditWrapper(t *testing.T) {
	// this test and its subtests cannot be run in parallel because of it's
	// dependency on the sysEventer

	cloudEventsConfig := TestEventerConfig(t, "TestEventer_RotateAuditWrapper")
	hclogConfig := TestEventerConfig(t, "TestEventer_RotateAuditWrapper", testWithSinkFormat(t, JSONHclogSinkFormat))

	testLock := &sync.Mutex{}
	testLogger := testLogger(t, testLock)

	testCtx := context.Background()
	tests := []struct {
		name            string
		w               wrapping.Wrapper
		config          TestConfig
		wantIsError     error
		wantErrContains string
	}{
		{
			name:            "missing-wrapper",
			config:          cloudEventsConfig,
			wantIsError:     ErrInvalidParameter,
			wantErrContains: "missing wrapper",
		},
		{
			name:   "valid-cloudevents",
			w:      testWrapper(t),
			config: cloudEventsConfig,
		},
		{
			name:   "valid-hclog",
			w:      testWrapper(t),
			config: hclogConfig,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			require.NoError(InitSysEventer(testLogger, testLock, "TestEventer_RotateAuditWrapper", WithEventerConfig(&tt.config.EventerConfig)))
			eventer := SysEventer()
			err := eventer.RotateAuditWrapper(testCtx, tt.w)
			if tt.wantIsError != nil {
				require.Error(err)
				assert.ErrorIs(err, tt.wantIsError)
				if tt.wantErrContains != "" {
					assert.Contains(err.Error(), tt.wantErrContains)
				}
				return
			}
			for _, n := range eventer.auditWrapperNodes {
				switch w := n.(type) {
				case *hclogFormatterFilter:
					assert.NotNil(w.signer)
				case *cloudEventsFormatterFilter:
					assert.NotNil(w.Signer)
				case *encrypt.Filter:
					assert.NotNil(w.Wrapper)
				}
			}
		})
	}
}
