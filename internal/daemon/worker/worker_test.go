// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package worker

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/config"
	"github.com/hashicorp/boundary/internal/daemon/worker/common"
	"github.com/hashicorp/boundary/internal/daemon/worker/session"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/event"
	"github.com/hashicorp/boundary/internal/gen/controller/servers/services"
	wpbs "github.com/hashicorp/boundary/internal/gen/worker/servers/services"
	"github.com/hashicorp/boundary/internal/server"
	"github.com/hashicorp/boundary/internal/util"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-secure-stdlib/configutil/v2"
	"github.com/hashicorp/go-secure-stdlib/listenerutil"
	"github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/registration"
	"github.com/hashicorp/nodeenrollment/rotation"
	nodeefile "github.com/hashicorp/nodeenrollment/storage/file"
	"github.com/hashicorp/nodeenrollment/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestWorkerNew(t *testing.T) {
	knownHostsPath := t.TempDir() + "/known_hosts"
	nonexistantKnownHostsPath := t.TempDir() + "/does_not_exist"
	corruptedKnownHostsPath := t.TempDir() + "/corrupted_known_hosts"

	file, err := os.Create(knownHostsPath)
	require.NoError(t, err)
	defer file.Close()

	signer, err := ssh.NewSignerFromKey(ed25519.NewKeyFromSeed([]byte("foobfoobfoobfoobfoobfoobfoobfoob")))
	require.NoError(t, err)
	line := fmt.Sprintf("::1 %s", string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	_, err = file.WriteString(line)

	require.NoError(t, err)

	corruptFile, err := os.Create(corruptedKnownHostsPath)
	require.NoError(t, err)
	defer corruptFile.Close()

	_, err = corruptFile.WriteString("this is not valid known hosts content")
	require.NoError(t, err)

	tests := []struct {
		name       string
		in         *Config
		expErr     bool
		expErrMsg  string
		assertions func(t *testing.T, w *Worker)
	}{
		{
			name:      "nil listeners",
			in:        &Config{Server: &base.Server{Listeners: nil}},
			expErr:    true,
			expErrMsg: "exactly one proxy listener is required",
		},
		{
			name:      "zero listeners",
			in:        &Config{Server: &base.Server{Listeners: []*base.ServerListener{}}},
			expErr:    true,
			expErrMsg: "exactly one proxy listener is required",
		},
		{
			name: "populated with nil values",
			in: &Config{
				Server: &base.Server{
					Listeners: []*base.ServerListener{
						nil,
						{Config: nil},
						{Config: &listenerutil.ListenerConfig{Purpose: nil}},
					},
				},
			},
			expErr:    true,
			expErrMsg: "exactly one proxy listener is required",
		},
		{
			name: "multiple purposes",
			in: &Config{
				Server: &base.Server{
					Listeners: []*base.ServerListener{
						nil,
						{Config: nil},
						{Config: &listenerutil.ListenerConfig{Purpose: []string{"api", "proxy"}}},
					},
				},
			},
			expErr:    true,
			expErrMsg: `found listener with multiple purposes "api,proxy"`,
		},
		{
			name: "too many proxy listeners",
			in: &Config{
				Server: &base.Server{
					Listeners: []*base.ServerListener{
						{Config: &listenerutil.ListenerConfig{Purpose: []string{"api"}}},
						{Config: &listenerutil.ListenerConfig{Purpose: []string{"proxy"}}},
						{Config: &listenerutil.ListenerConfig{Purpose: []string{"proxy"}}},
						{Config: &listenerutil.ListenerConfig{Purpose: []string{"cluster"}}},
					},
				},
			},
			expErr:    true,
			expErrMsg: "exactly one proxy listener is required",
		},
		{
			name: "valid listeners",
			in: &Config{
				Server: &base.Server{
					Listeners: []*base.ServerListener{
						{Config: &listenerutil.ListenerConfig{Purpose: []string{"api"}}},
						{Config: &listenerutil.ListenerConfig{Purpose: []string{"proxy"}}},
						{Config: &listenerutil.ListenerConfig{Purpose: []string{"cluster"}}},
					},
				},
			},
			expErr: false,
		},
		{
			name: "worker nonce func is set",
			in: &Config{
				Server: &base.Server{
					Listeners: []*base.ServerListener{
						{Config: &listenerutil.ListenerConfig{Purpose: []string{"proxy"}}},
					},
				},
			},
			expErr: false,
			assertions: func(t *testing.T, w *Worker) {
				require.NotNil(t, w.nonceFn)
			},
		},
		{
			name: "worker recording storage path is not set",
			in: &Config{
				Server: &base.Server{
					Listeners: []*base.ServerListener{
						{Config: &listenerutil.ListenerConfig{Purpose: []string{"proxy"}}},
					},
					Eventer: &event.Eventer{},
				},
				RawConfig: &config.Config{
					Worker: &config.Worker{},
					SharedConfig: &configutil.SharedConfig{
						DisableMlock: true,
					},
				},
			},
			expErr: false,
			assertions: func(t *testing.T, w *Worker) {
				assert.Equal(t, w.conf.RawConfig.Worker.RecordingStoragePath, "")
				assert.Equal(t, w.localStorageState.Load().(server.LocalStorageState).String(), server.NotConfiguredLocalStorageState.String())
			},
		},
		{
			name: "worker recording storage path is set",
			in: &Config{
				Server: &base.Server{
					Listeners: []*base.ServerListener{
						{Config: &listenerutil.ListenerConfig{Purpose: []string{"proxy"}}},
					},
				},
				RawConfig: &config.Config{
					Worker: &config.Worker{
						RecordingStoragePath: "/tmp",
					},
					SharedConfig: &configutil.SharedConfig{
						DisableMlock: true,
					},
				},
			},
			expErr: false,
			assertions: func(t *testing.T, w *Worker) {
				assert.Equal(t, w.conf.RawConfig.Worker.RecordingStoragePath, "/tmp")
				assert.Equal(t, w.localStorageState.Load().(server.LocalStorageState).String(), server.UnknownLocalStorageState.String())
			},
		},
		{
			name: "worker host service server is the unimplemented one by default",
			in: &Config{
				Server: &base.Server{
					Listeners: []*base.ServerListener{
						{Config: &listenerutil.ListenerConfig{Purpose: []string{"proxy"}}},
					},
				},
				RawConfig: &config.Config{
					Worker:       &config.Worker{},
					SharedConfig: &configutil.SharedConfig{DisableMlock: true},
				},
			},
			expErr: false,
			assertions: func(t *testing.T, w *Worker) {
				assert.Equal(t, wpbs.UnimplementedHostServiceServer{}, w.HostServiceServer)
			},
		},
		{
			name: "valid with no known hosts path",
			in: &Config{
				Server: &base.Server{
					Listeners: []*base.ServerListener{
						{Config: &listenerutil.ListenerConfig{Purpose: []string{"proxy"}}},
					},
				},
				RawConfig: &config.Config{
					SharedConfig: &configutil.SharedConfig{
						DisableMlock: true,
					},
				},
			},
			expErr: false,
			assertions: func(t *testing.T, w *Worker) {
				assert.Nil(t, w.SshKnownHostsCallback.Load())
			},
		},
		{
			name: "valid known hosts path",
			in: &Config{
				Server: &base.Server{
					Listeners: []*base.ServerListener{
						{Config: &listenerutil.ListenerConfig{Purpose: []string{"proxy"}}},
					},
				},
				RawConfig: &config.Config{
					Worker: &config.Worker{
						SshKnownHostsPath: knownHostsPath,
					},
					SharedConfig: &configutil.SharedConfig{
						DisableMlock: true,
					},
				},
			},
			expErr: false,
			assertions: func(t *testing.T, w *Worker) {
				assert.NotNil(t, w.SshKnownHostsCallback.Load())
			},
		},
		{
			name: "invalid known hosts path",
			in: &Config{
				Server: &base.Server{
					Listeners: []*base.ServerListener{
						{Config: &listenerutil.ListenerConfig{Purpose: []string{"proxy"}}},
					},
				},
				RawConfig: &config.Config{
					Worker: &config.Worker{
						SshKnownHostsPath: nonexistantKnownHostsPath,
					},
					SharedConfig: &configutil.SharedConfig{
						DisableMlock: true,
					},
				},
			},
			expErr:    true,
			expErrMsg: "no such file or directory",
		},
		{
			name: "corrupted known hosts file",
			in: &Config{
				Server: &base.Server{
					Listeners: []*base.ServerListener{
						{Config: &listenerutil.ListenerConfig{Purpose: []string{"proxy"}}},
					},
				},
				RawConfig: &config.Config{
					Worker: &config.Worker{
						SshKnownHostsPath: corruptedKnownHostsPath,
					},
					SharedConfig: &configutil.SharedConfig{
						DisableMlock: true,
					},
				},
			},
			expErr:    true,
			expErrMsg: "illegal base64 data at input byte",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// New() panics if these aren't set
			tt.in.Logger = hclog.Default()
			if tt.in.RawConfig == nil {
				tt.in.RawConfig = &config.Config{SharedConfig: &configutil.SharedConfig{DisableMlock: true}}
			}
			if util.IsNil(tt.in.Eventer) {
				require.NoError(t, event.InitSysEventer(hclog.Default(), &sync.Mutex{}, "worker_test", event.WithEventerConfig(&event.EventerConfig{})))
				t.Cleanup(func() { event.TestResetSystEventer(t) })
				tt.in.Eventer = event.SysEventer()
			}

			currentHostServiceFactory := hostServiceServerFactory
			hostServiceServerFactory = nil
			t.Cleanup(func() { hostServiceServerFactory = currentHostServiceFactory })

			w, err := New(context.Background(), tt.in)
			if tt.expErr {
				require.ErrorContains(t, err, tt.expErrMsg)
				require.Nil(t, w)
				return
			}

			require.NoError(t, err)
			if tt.assertions != nil {
				tt.assertions(t, w)
			}
		})
	}
}

func TestWorkerReload(t *testing.T) {
	knownHostsPath := t.TempDir() + "/known_hosts"
	file, err := os.Create(knownHostsPath)
	require.NoError(t, err)
	defer file.Close()

	signer, err := ssh.NewSignerFromKey(ed25519.NewKeyFromSeed([]byte("foobfoobfoobfoobfoobfoobfoobfoob")))
	require.NoError(t, err)

	dummyAddr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 22}
	line := fmt.Sprintf("github.com %s", string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	_, err = file.WriteString(line)
	require.NoError(t, err)

	t.Run("default config is the same as the reload config", func(t *testing.T) {
		require, assert := require.New(t), assert.New(t)
		cfg := &Config{
			Server: &base.Server{
				Logger:  hclog.Default(),
				Eventer: &event.Eventer{},
				Listeners: []*base.ServerListener{
					{Config: &listenerutil.ListenerConfig{Purpose: []string{"api"}}},
					{Config: &listenerutil.ListenerConfig{Purpose: []string{"proxy"}}},
					{Config: &listenerutil.ListenerConfig{Purpose: []string{"cluster"}}},
				},
			},
			RawConfig: &config.Config{
				SharedConfig: &configutil.SharedConfig{DisableMlock: true},
				Worker:       &config.Worker{},
			},
		}
		w, err := New(context.Background(), cfg)
		require.NoError(err)

		assert.Equal(int64(server.DefaultLiveness), w.successfulRoutingInfoGracePeriod.Load())
		assert.Equal(int64(server.DefaultLiveness), w.successfulSessionInfoGracePeriod.Load())
		assert.Equal(int64(server.DefaultLiveness), session.CloseCallTimeout.Load())

		assert.Equal(int64(common.DefaultRoutingInfoTimeout), w.routingInfoCallTimeoutDuration.Load())
		assert.Equal(int64(common.DefaultStatisticsTimeout), w.statisticsCallTimeoutDuration.Load())
		assert.Equal(int64(common.DefaultSessionInfoTimeout), w.sessionInfoCallTimeoutDuration.Load())

		assert.Equal(int64(server.DefaultLiveness), w.getDownstreamWorkersTimeoutDuration.Load())
		assert.Nil(w.SshKnownHostsCallback.Load())

		w.Reload(context.Background(), cfg.RawConfig)

		assert.Equal(int64(server.DefaultLiveness), w.successfulRoutingInfoGracePeriod.Load())
		assert.Equal(int64(server.DefaultLiveness), w.successfulSessionInfoGracePeriod.Load())
		assert.Equal(int64(server.DefaultLiveness), session.CloseCallTimeout.Load())

		assert.Equal(int64(common.DefaultRoutingInfoTimeout), w.routingInfoCallTimeoutDuration.Load())
		assert.Equal(int64(common.DefaultStatisticsTimeout), w.statisticsCallTimeoutDuration.Load())
		assert.Equal(int64(common.DefaultSessionInfoTimeout), w.sessionInfoCallTimeoutDuration.Load())

		assert.Equal(int64(server.DefaultLiveness), w.getDownstreamWorkersTimeoutDuration.Load())
		assert.Nil(w.SshKnownHostsCallback.Load())
	})

	t.Run("new config is the same as the reload config", func(t *testing.T) {
		require, assert := require.New(t), assert.New(t)
		cfg := &Config{
			Server: &base.Server{
				Logger:  hclog.Default(),
				Eventer: &event.Eventer{},
				Listeners: []*base.ServerListener{
					{Config: &listenerutil.ListenerConfig{Purpose: []string{"api"}}},
					{Config: &listenerutil.ListenerConfig{Purpose: []string{"proxy"}}},
					{Config: &listenerutil.ListenerConfig{Purpose: []string{"cluster"}}},
				},
			},
			RawConfig: &config.Config{
				SharedConfig: &configutil.SharedConfig{DisableMlock: true},
				Worker: &config.Worker{
					SuccessfulControllerRPCGracePeriodDuration: 5 * time.Second,
					ControllerRPCCallTimeoutDuration:           10 * time.Second,
					GetDownstreamWorkersTimeoutDuration:        20 * time.Second,
					SshKnownHostsPath:                          knownHostsPath,
				},
			},
		}
		w, err := New(context.Background(), cfg)
		require.NoError(err)

		assert.Equal(int64(5*time.Second), w.successfulRoutingInfoGracePeriod.Load())
		assert.Equal(int64(5*time.Second), w.successfulSessionInfoGracePeriod.Load())
		assert.Equal(w.successfulRoutingInfoGracePeriod.Load(), session.CloseCallTimeout.Load())

		assert.Equal(int64(10*time.Second), w.routingInfoCallTimeoutDuration.Load())
		assert.Equal(int64(10*time.Second), w.statisticsCallTimeoutDuration.Load())
		assert.Equal(int64(10*time.Second), w.sessionInfoCallTimeoutDuration.Load())

		assert.Equal(int64(20*time.Second), w.getDownstreamWorkersTimeoutDuration.Load())
		cb := w.SshKnownHostsCallback.Load()
		require.NotNil(cb)
		err = (*cb)("github.com:22", dummyAddr, signer.PublicKey())
		assert.NoError(err)

		w.Reload(context.Background(), cfg.RawConfig)

		assert.Equal(int64(5*time.Second), w.successfulRoutingInfoGracePeriod.Load())
		assert.Equal(int64(5*time.Second), w.successfulSessionInfoGracePeriod.Load())
		assert.Equal(w.successfulRoutingInfoGracePeriod.Load(), session.CloseCallTimeout.Load())

		assert.Equal(int64(10*time.Second), w.routingInfoCallTimeoutDuration.Load())
		assert.Equal(int64(10*time.Second), w.statisticsCallTimeoutDuration.Load())
		assert.Equal(int64(10*time.Second), w.sessionInfoCallTimeoutDuration.Load())

		assert.Equal(int64(20*time.Second), w.getDownstreamWorkersTimeoutDuration.Load())
		cb = w.SshKnownHostsCallback.Load()
		require.NotNil(cb)
		err = (*cb)("github.com:22", dummyAddr, signer.PublicKey())
		assert.NoError(err)
	})

	t.Run("new config is different", func(t *testing.T) {
		require, assert := require.New(t), assert.New(t)
		cfg := &Config{
			Server: &base.Server{
				Logger:  hclog.Default(),
				Eventer: &event.Eventer{},
				Listeners: []*base.ServerListener{
					{Config: &listenerutil.ListenerConfig{Purpose: []string{"api"}}},
					{Config: &listenerutil.ListenerConfig{Purpose: []string{"proxy"}}},
					{Config: &listenerutil.ListenerConfig{Purpose: []string{"cluster"}}},
				},
			},
			RawConfig: &config.Config{
				SharedConfig: &configutil.SharedConfig{DisableMlock: true},
				Worker: &config.Worker{
					SuccessfulControllerRPCGracePeriodDuration: 5 * time.Second,
					ControllerRPCCallTimeoutDuration:           10 * time.Second,
					GetDownstreamWorkersTimeoutDuration:        20 * time.Second,
					SshKnownHostsPath:                          knownHostsPath,
				},
			},
		}
		w, err := New(context.Background(), cfg)
		require.NoError(err)

		assert.Equal(int64(5*time.Second), w.successfulRoutingInfoGracePeriod.Load())
		assert.Equal(int64(5*time.Second), w.successfulSessionInfoGracePeriod.Load())
		assert.Equal(w.successfulRoutingInfoGracePeriod.Load(), session.CloseCallTimeout.Load())

		assert.Equal(int64(10*time.Second), w.routingInfoCallTimeoutDuration.Load())
		assert.Equal(int64(10*time.Second), w.statisticsCallTimeoutDuration.Load())
		assert.Equal(int64(10*time.Second), w.sessionInfoCallTimeoutDuration.Load())

		assert.Equal(int64(20*time.Second), w.getDownstreamWorkersTimeoutDuration.Load())
		cb := w.SshKnownHostsCallback.Load()
		require.NotNil(cb)
		err = (*cb)("github.com:22", dummyAddr, signer.PublicKey())
		assert.NoError(err)

		// Update the config with new values
		newKnownHostsFile := t.TempDir() + "/new_known_hosts"
		newFile, err := os.Create(newKnownHostsFile)
		require.NoError(err)
		defer newFile.Close()

		newSigner, err := ssh.NewSignerFromKey(ed25519.NewKeyFromSeed([]byte("noobnoobnoobnoobnoobnoobnoobnoob")))
		require.NoError(err)

		line := fmt.Sprintf("github.com %s", string(ssh.MarshalAuthorizedKey(newSigner.PublicKey())))
		_, err = newFile.WriteString(line)
		require.NoError(err)

		cfg.RawConfig.Worker.SuccessfulControllerRPCGracePeriodDuration = 30 * time.Second
		cfg.RawConfig.Worker.ControllerRPCCallTimeoutDuration = 35 * time.Second
		cfg.RawConfig.Worker.GetDownstreamWorkersTimeoutDuration = 40 * time.Second
		cfg.RawConfig.Worker.SshKnownHostsPath = newKnownHostsFile

		w.Reload(context.Background(), cfg.RawConfig)

		assert.Equal(int64(30*time.Second), w.successfulRoutingInfoGracePeriod.Load())
		assert.Equal(int64(30*time.Second), w.successfulSessionInfoGracePeriod.Load())
		assert.Equal(w.successfulRoutingInfoGracePeriod.Load(), session.CloseCallTimeout.Load())

		assert.Equal(int64(35*time.Second), w.routingInfoCallTimeoutDuration.Load())
		assert.Equal(int64(35*time.Second), w.statisticsCallTimeoutDuration.Load())
		assert.Equal(int64(35*time.Second), w.sessionInfoCallTimeoutDuration.Load())

		assert.Equal(int64(40*time.Second), w.getDownstreamWorkersTimeoutDuration.Load())
		cb = w.SshKnownHostsCallback.Load()
		require.NotNil(cb)

		// Old signer should fail
		err = (*cb)("github.com:22", dummyAddr, signer.PublicKey())
		assert.Error(err)
		// New signer should work
		err = (*cb)("github.com:22", dummyAddr, newSigner.PublicKey())
		assert.NoError(err)
	})
}

func TestSetupWorkerAuthStorage(t *testing.T) {
	ctx := context.Background()

	ts := db.TestWrapper(t)
	keyId, err := ts.KeyId(ctx)
	require.NoError(t, err)

	// First, just test the key ID is populated
	tmpDir := t.TempDir()
	tw := NewTestWorker(t, &TestWorkerOpts{
		WorkerAuthStorageKms:  ts,
		WorkerAuthStoragePath: tmpDir,
		DisableAutoStart:      true,
	})
	err = tw.Worker().Start()
	require.NoError(t, err)

	wKeyId, err := tw.Config().WorkerAuthStorageKms.KeyId(ctx)
	require.NoError(t, err)
	assert.Equal(t, keyId, wKeyId)

	// Create a fresh persistent dir for the following tests
	tmpDir = t.TempDir()

	// Get an initial set of authorized node credentials
	initStorage, err := nodeefile.New(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { initStorage.Cleanup(ctx) })
	_, err = rotation.RotateRootCertificates(ctx, initStorage)
	require.NoError(t, err)
	initNodeCreds, err := types.NewNodeCredentials(ctx, initStorage)
	require.NoError(t, err)
	req, err := initNodeCreds.CreateFetchNodeCredentialsRequest(ctx)
	require.NoError(t, err)
	_, err = registration.AuthorizeNode(ctx, initStorage, req)
	require.NoError(t, err)
	fetchResp, err := registration.FetchNodeCredentials(ctx, initStorage, req)
	require.NoError(t, err)
	initNodeCreds, err = initNodeCreds.HandleFetchNodeCredentialsResponse(ctx, initStorage, fetchResp)
	require.NoError(t, err)
	initKeyId, err := nodeenrollment.KeyIdFromPkix(initNodeCreds.CertificatePublicKeyPkix)
	require.NoError(t, err)

	nonce := make([]byte, nodeenrollment.NonceSize)
	_, err = rand.Reader.Read(nonce)
	require.NoError(t, err)

	// What's going on here: in each test we are simulating a startup of a
	// worker that has storage in various states. The input is a function to
	// modify the current state of node credentials by using the worker's
	// storage, but this happens before Start so we haven't done checking yet;
	// the assertions check what the final result is.
	tests := []struct {
		name                   string
		in                     func(*testing.T, nodeenrollment.Storage, *Worker)
		expKeyId               string // If set, the existing key ID to expect
		expRegistrationRequest bool   // Whether we should have seen a registration request generated
		expError               string // Some other error
	}{
		{
			name: "no creds",
			in: func(t *testing.T, storage nodeenrollment.Storage, w *Worker) {
				// Do nothing; in this case it will have already been cleared
			},
			expRegistrationRequest: true,
		},
		{
			name: "valid creds",
			in: func(t *testing.T, storage nodeenrollment.Storage, w *Worker) {
				// Store the authorized creds
				require.NoError(t, initNodeCreds.Store(ctx, storage))
			},
			expKeyId: initKeyId,
		},
		{
			name: "existing but not validated",
			in: func(t *testing.T, storage nodeenrollment.Storage, w *Worker) {
				creds := proto.Clone(initNodeCreds).(*types.NodeCredentials)
				creds.CertificateBundles = nil
				creds.RegistrationNonce = nonce
				require.NoError(t, creds.Store(ctx, storage))
			},
			expKeyId:               initKeyId,
			expRegistrationRequest: true,
		},
		{
			name: "existing and outside cert times", // Note that cert from next CA will already not be valid
			in: func(t *testing.T, storage nodeenrollment.Storage, w *Worker) {
				creds := proto.Clone(initNodeCreds).(*types.NodeCredentials)
				creds.CertificateBundles[0].CertificateNotBefore = timestamppb.New(time.Time{})
				creds.CertificateBundles[0].CertificateNotAfter = timestamppb.New(time.Time{})
				require.NoError(t, creds.Store(ctx, storage))
			},
			expRegistrationRequest: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tw := NewTestWorker(t, &TestWorkerOpts{
				WorkerAuthStoragePath: tmpDir,
				DisableAutoStart:      true,
			})

			// Always clear out storage that was there before, ignore errors
			storage, err := nodeefile.New(tw.Context(), nodeefile.WithBaseDirectory(tmpDir))
			require.NoError(t, err)
			_ = storage.Remove(ctx, &types.NodeCredentials{Id: string(nodeenrollment.CurrentId)})

			// Run node credentials modification
			tt.in(t, storage, tw.Worker())

			// Start up to run logic
			require.NoError(t, tw.Worker().Start())

			// Validate existing key was loaded or new key was created and loaded
			if tt.expKeyId != "" {
				assert.Equal(t, tt.expKeyId, tw.Worker().WorkerAuthCurrentKeyId.Load())
			} else {
				assert.NotEmpty(t, tw.Worker().WorkerAuthCurrentKeyId.Load())
			}
			if tt.expRegistrationRequest {
				assert.NotEmpty(t, tw.Worker().WorkerAuthRegistrationRequest)
			} else {
				assert.Empty(t, tw.Worker().WorkerAuthRegistrationRequest)
			}
		})
	}
}

func Test_Worker_getSessionTls(t *testing.T) {
	require.NoError(t, event.InitSysEventer(hclog.Default(), &sync.Mutex{}, "worker_test", event.WithEventerConfig(&event.EventerConfig{})))
	t.Cleanup(func() { event.TestResetSystEventer(t) })

	conf := &Config{
		Server: &base.Server{
			Listeners: []*base.ServerListener{
				{Config: &listenerutil.ListenerConfig{Purpose: []string{"api"}}},
				{Config: &listenerutil.ListenerConfig{Purpose: []string{"proxy"}}},
				{Config: &listenerutil.ListenerConfig{Purpose: []string{"cluster"}}},
			},
			Eventer: event.SysEventer(),
			Logger:  hclog.Default(),
		},
	}
	conf.RawConfig = &config.Config{SharedConfig: &configutil.SharedConfig{DisableMlock: true}}
	w, err := New(context.Background(), conf)
	require.NoError(t, err)
	w.lastRoutingInfoSuccess.Store(&LastRoutingInfo{RoutingInfoResponse: &services.RoutingInfoResponse{}, RoutingInfoTime: time.Now(), LastCalculatedUpstreams: nil})
	w.baseContext = context.Background()

	t.Run("success", func(t *testing.T) {
		m := &fakeManager{
			session: &fakeSession{
				cert: &x509.Certificate{
					Raw: []byte("something"),
				},
				privateKey: []byte("something_else"),
			},
		}
		hello := &tls.ClientHelloInfo{ServerName: "s_1234567890"}
		tlsConf, err := w.getSessionTls(m)(hello)
		require.NoError(t, err)
		require.Len(t, tlsConf.Certificates, 1)
		require.Len(t, tlsConf.Certificates[0].Certificate, 1)
		assert.Equal(t, m.session.cert.Raw, tlsConf.Certificates[0].Certificate[0])
		assert.Equal(t, m.session.cert, tlsConf.Certificates[0].Leaf)
		assert.Equal(t, ed25519.PrivateKey(m.session.privateKey), tlsConf.Certificates[0].PrivateKey)
		require.Len(t, tlsConf.NextProtos, 1)
		assert.Equal(t, "http/1.1", tlsConf.NextProtos[0])
		assert.Equal(t, tls.VersionTLS13, int(tlsConf.MinVersion))
		assert.Equal(t, tls.RequireAnyClientCert, tlsConf.ClientAuth)
		assert.Equal(t, true, tlsConf.InsecureSkipVerify)
		assert.NotNil(t, tlsConf.VerifyConnection)
	})
	t.Run("errors-on-empty-cert", func(t *testing.T) {
		m := &fakeManager{
			session: &fakeSession{
				cert:       nil,
				privateKey: []byte("something_else"),
			},
		}
		hello := &tls.ClientHelloInfo{ServerName: "s_1234567890"}
		_, err := w.getSessionTls(m)(hello)
		require.Error(t, err)
	})
	t.Run("errors-on-empty-cert-der", func(t *testing.T) {
		m := &fakeManager{
			session: &fakeSession{
				cert: &x509.Certificate{
					Raw: nil,
				},
				privateKey: []byte("something_else"),
			},
		}
		hello := &tls.ClientHelloInfo{ServerName: "s_1234567890"}
		_, err := w.getSessionTls(m)(hello)
		require.Error(t, err)
	})
	t.Run("errors-on-empty-private-key", func(t *testing.T) {
		m := &fakeManager{
			session: &fakeSession{
				cert: &x509.Certificate{
					Raw: []byte("something"),
				},
				privateKey: nil,
			},
		}
		hello := &tls.ClientHelloInfo{ServerName: "s_1234567890"}
		_, err := w.getSessionTls(m)(hello)
		require.Error(t, err)
	})
}

type fakeSession struct {
	cert       *x509.Certificate
	privateKey []byte

	session.Session
}

func (f *fakeSession) GetCertificate() *x509.Certificate {
	return f.cert
}

func (f *fakeSession) GetPrivateKey() []byte {
	return f.privateKey
}

type fakeManager struct {
	session.Manager

	session *fakeSession
}

func (f *fakeManager) LoadLocalSession(ctx context.Context, id string, workerId string) (session.Session, error) {
	return f.session, nil
}
