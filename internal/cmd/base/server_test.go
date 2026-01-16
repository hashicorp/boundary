// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package base

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/cmd/config"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/event"
	"github.com/hashicorp/go-hclog"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-kms-wrapping/v2/extras/multi"
	"github.com/hashicorp/go-secure-stdlib/configutil/v2"
	"github.com/hashicorp/go-secure-stdlib/listenerutil"
	"github.com/mitchellh/cli"
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

func TestServer_SetupKMSes_Purposes(t *testing.T) {
	tests := []struct {
		name            string
		purposes        []string
		wantErrContains string
	}{
		{
			name: "nil purposes",
		},
		{
			name:            "empty purpose",
			purposes:        []string{""},
			wantErrContains: "KMS block missing 'purpose'",
		},
		{
			name:            "unknown purpose",
			purposes:        []string{"foobar"},
			wantErrContains: "Unknown KMS purpose",
		},
		{
			name:     "single purpose",
			purposes: []string{globals.KmsPurposeRoot},
		},
		{
			name: "multi purpose",
			purposes: []string{
				globals.KmsPurposeRoot, globals.KmsPurposeRecovery, globals.KmsPurposeWorkerAuth, globals.KmsPurposeDownstreamWorkerAuth,
				globals.KmsPurposeWorkerAuthStorage, globals.KmsPurposeConfig, globals.KmsPurposeBsr,
			},
		},
		{
			name:            "previous root without root",
			purposes:        []string{globals.KmsPurposePreviousRoot},
			wantErrContains: fmt.Sprintf("KMS block contains '%s' without '%s'", globals.KmsPurposePreviousRoot, globals.KmsPurposeRoot),
		},
		{
			name:            "root and previous in the same stanza",
			purposes:        []string{globals.KmsPurposeRoot, globals.KmsPurposePreviousRoot},
			wantErrContains: fmt.Sprintf("KMS blocks with purposes '%s' and '%s' must have different key IDs", globals.KmsPurposeRoot, globals.KmsPurposePreviousRoot),
		},
		{
			name:            "duplicate root purposes",
			purposes:        []string{globals.KmsPurposeRoot, globals.KmsPurposeRoot},
			wantErrContains: fmt.Sprintf("Duplicate KMS block for purpose '%s'", globals.KmsPurposeRoot),
		},
		{
			name:            "duplicate previous root purposes",
			purposes:        []string{globals.KmsPurposePreviousRoot, globals.KmsPurposePreviousRoot},
			wantErrContains: fmt.Sprintf("Duplicate KMS block for purpose '%s'", globals.KmsPurposePreviousRoot),
		},
		{
			name:            "duplicate worker auth purposes",
			purposes:        []string{globals.KmsPurposeWorkerAuth, globals.KmsPurposeWorkerAuth},
			wantErrContains: fmt.Sprintf("Duplicate KMS block for purpose '%s'", globals.KmsPurposeWorkerAuth),
		},
		{
			name:            "duplicate worker auth storage purposes",
			purposes:        []string{globals.KmsPurposeWorkerAuthStorage, globals.KmsPurposeWorkerAuthStorage},
			wantErrContains: fmt.Sprintf("Duplicate KMS block for purpose '%s'", globals.KmsPurposeWorkerAuthStorage),
		},
		{
			name:            "duplicate bsr kms purposes",
			purposes:        []string{globals.KmsPurposeBsr, globals.KmsPurposeBsr},
			wantErrContains: fmt.Sprintf("Duplicate KMS block for purpose '%s'", globals.KmsPurposeBsr),
		},
		{
			name:            "duplicate recovery purposes",
			purposes:        []string{globals.KmsPurposeRecovery, globals.KmsPurposeRecovery},
			wantErrContains: fmt.Sprintf("Duplicate KMS block for purpose '%s'", globals.KmsPurposeRecovery),
		},
	}
	logger := hclog.Default()
	serLock := new(sync.Mutex)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			conf := &configutil.SharedConfig{
				Seals: []*configutil.KMS{
					{
						Type:    "aead",
						Purpose: tt.purposes,
					},
				},
			}
			s := NewServer(&Command{Context: context.Background()})
			require.NoError(s.SetupEventing(s.Context, logger, serLock, "setup-kms-testing"))
			err := s.SetupKMSes(s.Context, cli.NewMockUi(), &config.Config{SharedConfig: conf})

			if tt.wantErrContains != "" {
				require.Error(err)
				assert.Contains(err.Error(), tt.wantErrContains)
				return
			}

			require.NoError(err)
			for _, purpose := range tt.purposes {
				switch purpose {
				case globals.KmsPurposeRoot:
					assert.NotNil(s.RootKms)
				case globals.KmsPurposeWorkerAuth:
					assert.NotNil(s.WorkerAuthKms)
				case globals.KmsPurposeWorkerAuthStorage:
					assert.NotNil(s.WorkerAuthStorageKms)
				case globals.KmsPurposeRecovery:
					assert.NotNil(s.RecoveryKms)
				case globals.KmsPurposeBsr:
					assert.NotNil(s.BsrKms)
				}
			}
		})
	}
}

func TestServer_SetupKMSes_RootMigration(t *testing.T) {
	t.Parallel()
	t.Run("correctly-pools-root-and-previous", func(t *testing.T) {
		t.Parallel()
		assert, require := assert.New(t), require.New(t)
		logger := hclog.Default()
		serLock := new(sync.Mutex)
		conf := &configutil.SharedConfig{
			Seals: []*configutil.KMS{
				{
					Type: "aead",
					Purpose: []string{
						globals.KmsPurposeRoot,
					},
					Config: map[string]string{
						"key_id": "root",
					},
				},
				{
					Type: "aead",
					Purpose: []string{
						globals.KmsPurposePreviousRoot,
					},
					Config: map[string]string{
						"key_id": "previous_root",
					},
				},
			},
		}
		s := NewServer(&Command{Context: context.Background()})
		require.NoError(s.SetupEventing(s.Context, logger, serLock, "setup-kms-testing"))
		err := s.SetupKMSes(s.Context, cli.NewMockUi(), &config.Config{SharedConfig: conf})
		require.NoError(err)
		require.NotNil(s.RootKms)
		typ, err := s.RootKms.Type(s.Context)
		require.NoError(err)
		assert.Equal(wrapping.WrapperTypePooled, typ)
		// Ensure that the root is the encryptor
		keyId, err := s.RootKms.KeyId(s.Context)
		require.NoError(err)
		assert.Equal("root", keyId)
		// Ensure that the previous root is in the wrapper too
		assert.Equal([]string{"previous_root", "root"}, s.RootKms.(*multi.PooledWrapper).AllKeyIds())
	})
	t.Run("errors-on-previous-without-root", func(t *testing.T) {
		t.Parallel()
		require := require.New(t)
		logger := hclog.Default()
		serLock := new(sync.Mutex)
		conf := &configutil.SharedConfig{
			Seals: []*configutil.KMS{
				{
					Type: "aead",
					Purpose: []string{
						globals.KmsPurposePreviousRoot,
					},
				},
			},
		}
		s := NewServer(&Command{Context: context.Background()})
		require.NoError(s.SetupEventing(s.Context, logger, serLock, "setup-kms-testing"))
		err := s.SetupKMSes(s.Context, cli.NewMockUi(), &config.Config{SharedConfig: conf})
		require.Error(err)
	})
	t.Run("errors-on-previous-and-root-with-same-key-id", func(t *testing.T) {
		t.Parallel()
		require := require.New(t)
		logger := hclog.Default()
		serLock := new(sync.Mutex)
		conf := &configutil.SharedConfig{
			Seals: []*configutil.KMS{
				{
					Type: "aead",
					Purpose: []string{
						globals.KmsPurposeRoot,
					},
					Config: map[string]string{
						"key_id": "root",
					},
				},
				{
					Type: "aead",
					Purpose: []string{
						globals.KmsPurposePreviousRoot,
					},
					Config: map[string]string{
						"key_id": "root",
					},
				},
			},
		}
		s := NewServer(&Command{Context: context.Background()})
		require.NoError(s.SetupEventing(s.Context, logger, serLock, "setup-kms-testing"))
		err := s.SetupKMSes(s.Context, cli.NewMockUi(), &config.Config{SharedConfig: conf})
		require.Error(err)
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
				TelemetryEnabled:    &setFalse,
			})},
			want: func() event.EventerConfig {
				c := event.DefaultEventerConfig()
				c.AuditEnabled = true
				c.ObservationsEnabled = false
				c.SysEventsEnabled = false
				c.TelemetryEnabled = false
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
				TelemetryEnabled:    false,
			})},
			want: func() event.EventerConfig {
				c := event.DefaultEventerConfig()
				c.AuditEnabled = true
				c.ObservationsEnabled = false
				c.SysEventsEnabled = false
				c.TelemetryEnabled = false
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
		{
			name:   "opts-eventer-config-observation-telemetry-invalid",
			s:      &Server{},
			logger: testLogger,
			lock:   testLock,
			opt: []Option{WithEventFlags(&EventFlags{
				Format:              event.JSONSinkFormat,
				AuditEnabled:        &setTrue,
				ObservationsEnabled: &setFalse,
				SysEventsEnabled:    &setFalse,
				TelemetryEnabled:    &setTrue,
			})},
			wantErrIs:       event.ErrInvalidParameter,
			wantErrContains: "telemetry events require observation event to be enabled",
		},
		{
			name:   "opts-eventer-config-observation-on-telemetry-off",
			s:      &Server{},
			logger: testLogger,
			lock:   testLock,
			opt: []Option{WithEventFlags(&EventFlags{
				Format:              event.JSONSinkFormat,
				AuditEnabled:        &setFalse,
				ObservationsEnabled: &setTrue,
				SysEventsEnabled:    &setFalse,
				TelemetryEnabled:    &setFalse,
			})},
			want: func() event.EventerConfig {
				c := event.DefaultEventerConfig()
				c.AuditEnabled = false
				c.ObservationsEnabled = true
				c.SysEventsEnabled = false
				c.TelemetryEnabled = false
				return *c
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			event.TestResetSystEventer(t)

			err := tt.s.SetupEventing(context.Background(), tt.logger, tt.lock, tt.name, tt.opt...)
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

func TestSetupWorkerPublicAddress(t *testing.T) {
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
			name: "setting public address directly with ipv4",
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
			name: "setting public address directly with ipv4:port",
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
			name: "setting public address directly with invalid ipv6",
			inputConfig: &config.Config{
				SharedConfig: &configutil.SharedConfig{
					Listeners: []*listenerutil.ListenerConfig{},
				},
				Worker: &config.Worker{
					PublicAddr: "[2001:4860:4860:0:0:0:8888]",
				},
			},
			inputFlagValue: "",
			expErr:         true,
			expErrStr:      "Error normalizing worker address",
		},
		{
			name: "setting public address directly with ipv6 but no brackets",
			inputConfig: &config.Config{
				SharedConfig: &configutil.SharedConfig{
					Listeners: []*listenerutil.ListenerConfig{},
				},
				Worker: &config.Worker{
					PublicAddr: "2001:4860:4860:0:0:0:0:8888",
				},
			},
			inputFlagValue:   "",
			expErr:           false,
			expErrStr:        "",
			expPublicAddress: "[2001:4860:4860::8888]:9202",
		},
		{
			name: "setting public address directly with ipv6",
			inputConfig: &config.Config{
				SharedConfig: &configutil.SharedConfig{
					Listeners: []*listenerutil.ListenerConfig{},
				},
				Worker: &config.Worker{
					PublicAddr: "2001:4860:4860:0:0:0:0:8888",
				},
			},
			inputFlagValue:   "",
			expErr:           false,
			expErrStr:        "",
			expPublicAddress: "[2001:4860:4860::8888]:9202",
		},
		{
			name: "setting public address directly with ipv6:port",
			inputConfig: &config.Config{
				SharedConfig: &configutil.SharedConfig{
					Listeners: []*listenerutil.ListenerConfig{},
				},
				Worker: &config.Worker{
					PublicAddr: "[2001:4860:4860:0:0:0:0:8888]:8080",
				},
			},
			inputFlagValue:   "",
			expErr:           false,
			expErrStr:        "",
			expPublicAddress: "[2001:4860:4860::8888]:8080",
		},
		{
			name: "setting public address directly with abbreviated ipv6",
			inputConfig: &config.Config{
				SharedConfig: &configutil.SharedConfig{
					Listeners: []*listenerutil.ListenerConfig{},
				},
				Worker: &config.Worker{
					PublicAddr: "2001:4860:4860::8888",
				},
			},
			inputFlagValue:   "",
			expErr:           false,
			expErrStr:        "",
			expPublicAddress: "[2001:4860:4860::8888]:9202",
		},
		{
			name: "setting public address directly with abbreviated ipv6:port",
			inputConfig: &config.Config{
				SharedConfig: &configutil.SharedConfig{
					Listeners: []*listenerutil.ListenerConfig{},
				},
				Worker: &config.Worker{
					PublicAddr: "[2001:4860:4860::8888]:8080",
				},
			},
			inputFlagValue:   "",
			expErr:           false,
			expErrStr:        "",
			expPublicAddress: "[2001:4860:4860::8888]:8080",
		},
		{
			name: "setting public address to env var",
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
			name: "setting public address to env var that points to template",
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
				t.Setenv("TEST_ENV_VAR_FOR_WORKER_ADDR", `{{ GetAllInterfaces | include "flags" "loopback" | include "type" "IPV4" | join "address" " " }}`)
			},
			expErr:           false,
			expErrStr:        "",
			expPublicAddress: "127.0.0.1:9202",
		},
		{
			name: "setting public address to ip template",
			inputConfig: &config.Config{
				SharedConfig: &configutil.SharedConfig{
					Listeners: []*listenerutil.ListenerConfig{},
				},
				Worker: &config.Worker{
					PublicAddr: `{{ GetAllInterfaces | include "flags" "loopback" | include "type" "IPV4" | join "address" " " }}`,
				},
			},
			inputFlagValue:   "",
			expErr:           false,
			expErrStr:        "",
			expPublicAddress: "127.0.0.1:9202",
		},
		{
			name: "setting public address to multiline ip template",
			inputConfig: &config.Config{
				SharedConfig: &configutil.SharedConfig{
					Listeners: []*listenerutil.ListenerConfig{},
				},
				Worker: &config.Worker{
					PublicAddr: `{{ with $local := GetAllInterfaces | include "flags" "loopback" | include "type" "IPV4" -}}
					{{- $local | join "address" " " -}}
				  {{- end }}`,
				},
			},
			inputFlagValue:   "",
			expErr:           false,
			expErrStr:        "",
			expPublicAddress: "127.0.0.1:9202",
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
			name: "using flag value with ip template",
			inputConfig: &config.Config{
				SharedConfig: &configutil.SharedConfig{
					Listeners: []*listenerutil.ListenerConfig{},
				},
				Worker: &config.Worker{},
			},
			inputFlagValue:   `{{ GetAllInterfaces | include "flags" "loopback" | include "type" "IPV4" | join "address" " " }}`,
			expErr:           false,
			expErrStr:        "",
			expPublicAddress: "127.0.0.1:9202",
		},
		{
			name: "using flag value with multiline ip template",
			inputConfig: &config.Config{
				SharedConfig: &configutil.SharedConfig{
					Listeners: []*listenerutil.ListenerConfig{},
				},
				Worker: &config.Worker{},
			},
			inputFlagValue: `{{ with $local := GetAllInterfaces | include "flags" "loopback" | include "type" "IPV4" -}}
			  {{- $local | join "address" " " -}}
			{{- end }}`,
			expErr:           false,
			expErrStr:        "",
			expPublicAddress: "127.0.0.1:9202",
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
			name: "read unix address from listeners ip only",
			inputConfig: &config.Config{
				SharedConfig: &configutil.SharedConfig{
					Listeners: []*listenerutil.ListenerConfig{
						{Purpose: []string{"proxy"}, Address: "someaddr", Type: "unix"},
					},
				},
				Worker: &config.Worker{},
			},
			expErr:           false,
			expErrStr:        "",
			expPublicAddress: "someaddr:9202",
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
			name: "using flag value to provoke error in SplitHostPort",
			inputConfig: &config.Config{
				SharedConfig: &configutil.SharedConfig{
					Listeners: []*listenerutil.ListenerConfig{},
				},
				Worker: &config.Worker{},
			},
			inputFlagValue:   "abc::123:::",
			expErr:           true,
			expErrStr:        "Error splitting public adddress host/port: too many colons in address",
			expPublicAddress: "",
		},
		{
			name: "bad ip template",
			inputConfig: &config.Config{
				SharedConfig: &configutil.SharedConfig{
					Listeners: []*listenerutil.ListenerConfig{},
				},
				Worker: &config.Worker{},
			},
			inputFlagValue:   "{{ somethingthatdoesntexist }}",
			expErr:           true,
			expErrStr:        "Error parsing IP template on worker public addr: unable to parse address template \"{{ somethingthatdoesntexist }}\": unable to parse template \"{{ somethingthatdoesntexist }}\": template: sockaddr.Parse:1: function \"somethingthatdoesntexist\" not defined",
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
