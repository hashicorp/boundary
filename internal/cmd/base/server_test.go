package base

import (
	"context"
	"sync"
	"testing"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/observability/event"
	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_NewServer(t *testing.T) {
	t.Run("assert-require-no-nil-fields", func(t *testing.T) {
		assert := assert.New(t)
		s := NewServer(&Command{})
		assert.Equal(s.Command, &Command{})
		assert.NotNil(s.InfoKeys)
		assert.NotNil(s.Info)
		assert.NotNil(s.SecureRandomReader)
		assert.NotNil(s.ReloadFuncsLock)
		assert.NotNil(s.ReloadFuncs)
		assert.NotNil(s.StderrLock)
	})
}

func TestServer_SetupEventing(t *testing.T) {
	// DO NOT run these test in parallel since they have a dependency on
	// event.sysEventer

	testLock := &sync.Mutex{}
	testLogger := hclog.New(&hclog.LoggerOptions{
		Mutex: testLock,
	})
	setTrue := true
	setFalse := false

	tests := []struct {
		name            string
		s               *Server
		logger          hclog.Logger
		lock            *sync.Mutex
		opt             []Option
		want            event.EventerConfig
		wantErrMatch    *errors.Template
		wantErrIs       error
		wantErrContains string
	}{
		{
			name:            "missing-logger",
			s:               &Server{},
			lock:            testLock,
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing logger",
		},
		{
			name:            "missing-serialization-lock",
			s:               &Server{},
			logger:          testLogger,
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing serialization lock",
		},
		{
			name:   "opts-none",
			s:      &Server{},
			logger: testLogger,
			lock:   testLock,
			want:   *event.DefaultEventerConfig(),
		},
		{
			name:   "opts-event-flags",
			s:      &Server{},
			logger: testLogger,
			lock:   testLock,
			opt: []Option{WithEventFlags(&EventFlags{
				Format:              event.JSONSinkFormat,
				AuditEnabled:        &setTrue,
				ObservationsEnabled: &setFalse,
				SysEventsEnabled:    &setFalse,
			})},
			want: func() event.EventerConfig {
				c := event.DefaultEventerConfig()
				c.AuditEnabled = true
				c.ObservationsEnabled = false
				c.SysEventsEnabled = false
				return *c
			}(),
		},
		{
			name:   "opts-event-flags-invalid",
			s:      &Server{},
			logger: testLogger,
			lock:   testLock,
			opt: []Option{WithEventFlags(&EventFlags{
				Format: "invalid-format",
			})},
			wantErrIs:       event.ErrInvalidParameter,
			wantErrContains: "not a valid sink format",
		},
		{
			name:   "opts-eventer-config",
			s:      &Server{},
			logger: testLogger,
			lock:   testLock,
			opt: []Option{WithEventerConfig(&event.EventerConfig{
				ObservationsEnabled: false,
				SysEventsEnabled:    false,
				AuditEnabled:        true,
			})},
			want: func() event.EventerConfig {
				c := event.DefaultEventerConfig()
				c.AuditEnabled = true
				c.ObservationsEnabled = false
				c.SysEventsEnabled = false
				return *c
			}(),
		},
		{
			name:   "opts-eventer-config-invalid",
			s:      &Server{},
			logger: testLogger,
			lock:   testLock,
			opt: []Option{WithEventerConfig(&event.EventerConfig{
				Sinks: []*event.SinkConfig{
					{
						Format: "invalid-format",
					},
				},
			})},
			wantErrIs:       event.ErrInvalidParameter,
			wantErrContains: "sink 0 is invalid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			event.TestResetSystEventer(t)

			err := tt.s.SetupEventing(tt.logger, tt.lock, tt.name, tt.opt...)
			if tt.wantErrMatch != nil || tt.wantErrIs != nil {
				require.Error(err)
				assert.Nil(tt.s.Eventer)
				assert.Nil(event.SysEventer())
				if tt.wantErrMatch != nil {
					assert.Truef(errors.Match(tt.wantErrMatch, err), "want %q and got %q", tt.wantErrMatch.Code, err.Error())
				}
				if tt.wantErrIs != nil {
					assert.ErrorIs(err, tt.wantErrIs)
				}
				if tt.wantErrContains != "" {
					assert.Contains(err.Error(), tt.wantErrContains)
				}
				return
			}
			require.NoError(err)
			assert.Equal(tt.want, event.TestGetEventerConfig(t, tt.s.Eventer))
		})
	}
}

func TestServer_AddEventerToContext(t *testing.T) {
	testLock := &sync.Mutex{}
	testLogger := hclog.New(&hclog.LoggerOptions{
		Mutex: testLock,
	})
	testEventer, err := event.NewEventer(testLogger, testLock, "TestServer_AddEventerToContext", event.EventerConfig{})
	require.NoError(t, err)
	tests := []struct {
		name            string
		s               Server
		ctx             context.Context
		wantErrMatch    *errors.Template
		wantErrContains string
	}{
		{
			name:            "missing-eventer",
			s:               Server{},
			ctx:             context.Background(),
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing server eventer",
		},
		{
			name: "valid",
			s:    Server{Eventer: testEventer},
			ctx:  context.Background(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			gotCtx, err := tt.s.AddEventerToContext(tt.ctx)
			if tt.wantErrMatch != nil {
				require.Error(err)
				assert.Nil(gotCtx)
				assert.Truef(errors.Match(tt.wantErrMatch, err), "want %q and got %q", tt.wantErrMatch.Code, err.Error())
				if tt.wantErrContains != "" {
					assert.Contains(err.Error(), tt.wantErrContains)
				}
				return
			}
			require.NoError(err)
			e, ok := event.EventerFromContext(gotCtx)
			require.Truef(ok, "unable to get eventer from context")
			assert.NotNil(e)
			assert.Equal(tt.s.Eventer, e)
		})
	}
}
