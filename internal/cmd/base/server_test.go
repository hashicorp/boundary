package base

import (
	"context"
	"sync"
	"testing"

	"github.com/hashicorp/boundary/internal/cmd/config"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/observability/event"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-secure-stdlib/configutil"
	"github.com/hashicorp/go-secure-stdlib/listenerutil"
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

func TestSetupControllerPublicClusterAddress(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name                    string
		inputConfig             *config.Config
		inputFlagValue          string
		stateFn                 func(t *testing.T)
		expErr                  bool
		expErrStr               string
		expPublicClusterAddress string
	}{
		{
			name: "nil controller",
			inputConfig: &config.Config{
				SharedConfig: &configutil.SharedConfig{
					Listeners: []*listenerutil.ListenerConfig{},
				},
				Controller: nil,
			},
			inputFlagValue:          "",
			expErr:                  false,
			expErrStr:               "",
			expPublicClusterAddress: ":9201",
		},
		{
			name: "setting public cluster address directly with ip",
			inputConfig: &config.Config{
				SharedConfig: &configutil.SharedConfig{
					Listeners: []*listenerutil.ListenerConfig{},
				},
				Controller: &config.Controller{
					PublicClusterAddr: "127.0.0.1",
				},
			},
			inputFlagValue:          "",
			expErr:                  false,
			expErrStr:               "",
			expPublicClusterAddress: "127.0.0.1:9201",
		},
		{
			name: "setting public cluster address directly with ip:port",
			inputConfig: &config.Config{
				SharedConfig: &configutil.SharedConfig{
					Listeners: []*listenerutil.ListenerConfig{},
				},
				Controller: &config.Controller{
					PublicClusterAddr: "127.0.0.1:8080",
				},
			},
			inputFlagValue:          "",
			expErr:                  false,
			expErrStr:               "",
			expPublicClusterAddress: "127.0.0.1:8080",
		},
		{
			name: "setting pubic cluster address to env var",
			inputConfig: &config.Config{
				SharedConfig: &configutil.SharedConfig{
					Listeners: []*listenerutil.ListenerConfig{},
				},
				Controller: &config.Controller{
					PublicClusterAddr: "env://TEST_ENV_VAR_FOR_CONTROLLER_ADDR",
				},
			},
			inputFlagValue: "",
			stateFn: func(t *testing.T) {
				t.Setenv("TEST_ENV_VAR_FOR_CONTROLLER_ADDR", "127.0.0.1:8080")
			},
			expErr:                  false,
			expErrStr:               "",
			expPublicClusterAddress: "127.0.0.1:8080",
		},
		{
			name: "using flag value with ip only",
			inputConfig: &config.Config{
				SharedConfig: &configutil.SharedConfig{
					Listeners: []*listenerutil.ListenerConfig{},
				},
				Controller: &config.Controller{},
			},
			inputFlagValue:          "127.0.0.1",
			expErr:                  false,
			expErrStr:               "",
			expPublicClusterAddress: "127.0.0.1:9201",
		},
		{
			name: "using flag value with ip:port",
			inputConfig: &config.Config{
				SharedConfig: &configutil.SharedConfig{
					Listeners: []*listenerutil.ListenerConfig{},
				},
				Controller: &config.Controller{},
			},
			inputFlagValue:          "127.0.0.1:8080",
			expErr:                  false,
			expErrStr:               "",
			expPublicClusterAddress: "127.0.0.1:8080",
		},
		{
			name: "using flag value to point to env var with ip only",
			inputConfig: &config.Config{
				SharedConfig: &configutil.SharedConfig{
					Listeners: []*listenerutil.ListenerConfig{},
				},
				Controller: &config.Controller{},
			},
			inputFlagValue: "env://TEST_ENV_VAR_FOR_CONTROLLER_ADDR",
			stateFn: func(t *testing.T) {
				t.Setenv("TEST_ENV_VAR_FOR_CONTROLLER_ADDR", "127.0.0.1")
			},
			expErr:                  false,
			expErrStr:               "",
			expPublicClusterAddress: "127.0.0.1:9201",
		},
		{
			name: "using flag value to point to env var with ip:port",
			inputConfig: &config.Config{
				SharedConfig: &configutil.SharedConfig{
					Listeners: []*listenerutil.ListenerConfig{},
				},
				Controller: &config.Controller{},
			},
			inputFlagValue: "env://TEST_ENV_VAR_FOR_CONTROLLER_ADDR",
			stateFn: func(t *testing.T) {
				t.Setenv("TEST_ENV_VAR_FOR_CONTROLLER_ADDR", "127.0.0.1:8080")
			},
			expErr:                  false,
			expErrStr:               "",
			expPublicClusterAddress: "127.0.0.1:8080",
		},
		{
			name: "read address from listeners ip only",
			inputConfig: &config.Config{
				SharedConfig: &configutil.SharedConfig{
					Listeners: []*listenerutil.ListenerConfig{
						{Purpose: []string{"cluster"}, Address: "127.0.0.1"},
					},
				},
				Controller: &config.Controller{},
			},
			expErr:                  false,
			expErrStr:               "",
			expPublicClusterAddress: "127.0.0.1:9201",
		},
		{
			name: "read address from listeners ip:port",
			inputConfig: &config.Config{
				SharedConfig: &configutil.SharedConfig{
					Listeners: []*listenerutil.ListenerConfig{
						{Purpose: []string{"cluster"}, Address: "127.0.0.1:8080"},
					},
				},
				Controller: &config.Controller{},
			},
			expErr:                  false,
			expErrStr:               "",
			expPublicClusterAddress: "127.0.0.1:8080",
		},
		{
			name: "read address from listeners is ignored on different purpose",
			inputConfig: &config.Config{
				SharedConfig: &configutil.SharedConfig{
					Listeners: []*listenerutil.ListenerConfig{
						{Purpose: []string{"somethingelse"}, Address: "127.0.0.1:8080"},
					},
				},
				Controller: &config.Controller{},
			},
			expErr:                  false,
			expErrStr:               "",
			expPublicClusterAddress: ":9201",
		},
		{
			name: "using flag value to point to nonexistent file",
			inputConfig: &config.Config{
				SharedConfig: &configutil.SharedConfig{
					Listeners: []*listenerutil.ListenerConfig{},
				},
				Controller: &config.Controller{},
			},
			inputFlagValue:          "file://this_doesnt_exist_for_sure",
			expErr:                  true,
			expErrStr:               "Error parsing public cluster addr: error reading file at file://this_doesnt_exist_for_sure: open this_doesnt_exist_for_sure: no such file or directory",
			expPublicClusterAddress: "",
		},
		{
			name: "using flag value to provoke error in SpitHostPort",
			inputConfig: &config.Config{
				SharedConfig: &configutil.SharedConfig{
					Listeners: []*listenerutil.ListenerConfig{},
				},
				Controller: &config.Controller{},
			},
			inputFlagValue:          "abc::123",
			expErr:                  true,
			expErrStr:               "Error splitting public cluster adddress host/port: address abc::123: too many colons in address",
			expPublicClusterAddress: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.stateFn != nil {
				tt.stateFn(t)
			}
			s := Server{}
			err := s.SetupControllerPublicClusterAddress(tt.inputConfig, tt.inputFlagValue)
			if tt.expErr {
				require.EqualError(t, err, tt.expErrStr)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, tt.inputConfig.Controller)
			require.Equal(t, tt.expPublicClusterAddress, tt.inputConfig.Controller.PublicClusterAddr)
		})
	}
}

func TestSetupWorkerPublicAddress(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name             string
		inputConfig      *config.Config
		inputFlagValue   string
		stateFn          func(t *testing.T)
		expErr           bool
		expErrStr        string
		expPublicAddress string
	}{
		{
			name: "nil worker",
			inputConfig: &config.Config{
				SharedConfig: &configutil.SharedConfig{
					Listeners: []*listenerutil.ListenerConfig{},
				},
				Worker: nil,
			},
			inputFlagValue:   "",
			expErr:           false,
			expErrStr:        "",
			expPublicAddress: ":9202",
		},
		{
			name: "setting public address directly with ip",
			inputConfig: &config.Config{
				SharedConfig: &configutil.SharedConfig{
					Listeners: []*listenerutil.ListenerConfig{},
				},
				Worker: &config.Worker{
					PublicAddr: "127.0.0.1",
				},
			},
			inputFlagValue:   "",
			expErr:           false,
			expErrStr:        "",
			expPublicAddress: "127.0.0.1:9202",
		},
		{
			name: "setting public address directly with ip:port",
			inputConfig: &config.Config{
				SharedConfig: &configutil.SharedConfig{
					Listeners: []*listenerutil.ListenerConfig{},
				},
				Worker: &config.Worker{
					PublicAddr: "127.0.0.1:8080",
				},
			},
			inputFlagValue:   "",
			expErr:           false,
			expErrStr:        "",
			expPublicAddress: "127.0.0.1:8080",
		},
		{
			name: "setting pubic address to env var",
			inputConfig: &config.Config{
				SharedConfig: &configutil.SharedConfig{
					Listeners: []*listenerutil.ListenerConfig{},
				},
				Worker: &config.Worker{
					PublicAddr: "env://TEST_ENV_VAR_FOR_WORKER_ADDR",
				},
			},
			inputFlagValue: "",
			stateFn: func(t *testing.T) {
				t.Setenv("TEST_ENV_VAR_FOR_WORKER_ADDR", "127.0.0.1:8080")
			},
			expErr:           false,
			expErrStr:        "",
			expPublicAddress: "127.0.0.1:8080",
		},
		{
			name: "using flag value with ip only",
			inputConfig: &config.Config{
				SharedConfig: &configutil.SharedConfig{
					Listeners: []*listenerutil.ListenerConfig{},
				},
				Worker: &config.Worker{},
			},
			inputFlagValue:   "127.0.0.1",
			expErr:           false,
			expErrStr:        "",
			expPublicAddress: "127.0.0.1:9202",
		},
		{
			name: "using flag value with ip:port",
			inputConfig: &config.Config{
				SharedConfig: &configutil.SharedConfig{
					Listeners: []*listenerutil.ListenerConfig{},
				},
				Worker: &config.Worker{},
			},
			inputFlagValue:   "127.0.0.1:8080",
			expErr:           false,
			expErrStr:        "",
			expPublicAddress: "127.0.0.1:8080",
		},
		{
			name: "using flag value to point to env var with ip only",
			inputConfig: &config.Config{
				SharedConfig: &configutil.SharedConfig{
					Listeners: []*listenerutil.ListenerConfig{},
				},
				Worker: &config.Worker{},
			},
			inputFlagValue: "env://TEST_ENV_VAR_FOR_WORKER_ADDR",
			stateFn: func(t *testing.T) {
				t.Setenv("TEST_ENV_VAR_FOR_WORKER_ADDR", "127.0.0.1")
			},
			expErr:           false,
			expErrStr:        "",
			expPublicAddress: "127.0.0.1:9202",
		},
		{
			name: "using flag value to point to env var with ip:port",
			inputConfig: &config.Config{
				SharedConfig: &configutil.SharedConfig{
					Listeners: []*listenerutil.ListenerConfig{},
				},
				Worker: &config.Worker{},
			},
			inputFlagValue: "env://TEST_ENV_VAR_FOR_WORKER_ADDR",
			stateFn: func(t *testing.T) {
				t.Setenv("TEST_ENV_VAR_FOR_WORKER_ADDR", "127.0.0.1:8080")
			},
			expErr:           false,
			expErrStr:        "",
			expPublicAddress: "127.0.0.1:8080",
		},
		{
			name: "read address from listeners ip only",
			inputConfig: &config.Config{
				SharedConfig: &configutil.SharedConfig{
					Listeners: []*listenerutil.ListenerConfig{
						{Purpose: []string{"proxy"}, Address: "127.0.0.1"},
					},
				},
				Worker: &config.Worker{},
			},
			expErr:           false,
			expErrStr:        "",
			expPublicAddress: "127.0.0.1:9202",
		},
		{
			name: "read address from listeners ip:port",
			inputConfig: &config.Config{
				SharedConfig: &configutil.SharedConfig{
					Listeners: []*listenerutil.ListenerConfig{
						{Purpose: []string{"proxy"}, Address: "127.0.0.1:8080"},
					},
				},
				Worker: &config.Worker{},
			},
			expErr:           false,
			expErrStr:        "",
			expPublicAddress: "127.0.0.1:8080",
		},
		{
			name: "read address from listeners is ignored on different purpose",
			inputConfig: &config.Config{
				SharedConfig: &configutil.SharedConfig{
					Listeners: []*listenerutil.ListenerConfig{
						{Purpose: []string{"somethingelse"}, Address: "127.0.0.1:8080"},
					},
				},
				Worker: &config.Worker{},
			},
			expErr:           false,
			expErrStr:        "",
			expPublicAddress: ":9202",
		},
		{
			name: "using flag value to point to nonexistent file",
			inputConfig: &config.Config{
				SharedConfig: &configutil.SharedConfig{
					Listeners: []*listenerutil.ListenerConfig{},
				},
				Worker: &config.Worker{},
			},
			inputFlagValue:   "file://this_doesnt_exist_for_sure",
			expErr:           true,
			expErrStr:        "Error parsing public addr: error reading file at file://this_doesnt_exist_for_sure: open this_doesnt_exist_for_sure: no such file or directory",
			expPublicAddress: "",
		},
		{
			name: "using flag value to provoke error in SpitHostPort",
			inputConfig: &config.Config{
				SharedConfig: &configutil.SharedConfig{
					Listeners: []*listenerutil.ListenerConfig{},
				},
				Worker: &config.Worker{},
			},
			inputFlagValue:   "abc::123",
			expErr:           true,
			expErrStr:        "Error splitting public adddress host/port: address abc::123: too many colons in address",
			expPublicAddress: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.stateFn != nil {
				tt.stateFn(t)
			}
			s := Server{}
			err := s.SetupWorkerPublicAddress(tt.inputConfig, tt.inputFlagValue)
			if tt.expErr {
				require.EqualError(t, err, tt.expErrStr)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, tt.inputConfig.Worker)
			require.Equal(t, tt.expPublicAddress, tt.inputConfig.Worker.PublicAddr)
		})
	}
}
