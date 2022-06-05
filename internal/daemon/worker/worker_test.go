package worker

import (
	"context"
	"crypto/rand"
	"os"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/config"
	"github.com/hashicorp/boundary/internal/db"
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
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestWorkerNew(t *testing.T) {
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// New() panics if these aren't set
			tt.in.Logger = hclog.Default()
			tt.in.RawConfig = &config.Config{SharedConfig: &configutil.SharedConfig{DisableMlock: true}}

			w, err := New(tt.in)
			if tt.expErr {
				require.EqualError(t, err, tt.expErrMsg)
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

func TestSetupWorkerAuthStorage(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	ts := db.TestWrapper(t)
	keyId, err := ts.KeyId(ctx)
	require.NoError(t, err)

	// First, just test the key ID is populated
	tmpDir, err := os.MkdirTemp("", "")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, os.RemoveAll(tmpDir)) })
	tw := NewTestWorker(t, &TestWorkerOpts{
		WorkerAuthStorageKms:  ts,
		WorkerAuthStoragePath: tmpDir,
		DisableAutoStart:      true,
	})
	t.Cleanup(tw.Shutdown)
	err = tw.Worker().Start()
	require.NoError(t, err)

	wKeyId, err := tw.Config().WorkerAuthStorageKms.KeyId(ctx)
	require.NoError(t, err)
	assert.Equal(t, keyId, wKeyId)

	// Create a fresh persistent dir for the following tests
	tmpDir, err = os.MkdirTemp("", "")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, os.RemoveAll(tmpDir)) })

	// Get an initial set of authorized node credentials
	initStorage, err := nodeefile.New(ctx)
	require.NoError(t, err)
	t.Cleanup(initStorage.Cleanup)
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
		in                     func(t *testing.T, w *Worker)
		expKeyId               string // If set, the existing key ID to expect
		expCreation            bool   // Whether we should expect a new key ID
		expRegistrationRequest bool   // Whether we should have seen a registration request generated
		expError               string // Some other error
	}{
		{
			name: "no creds",
			in: func(t *testing.T, w *Worker) {
				// Do nothing; in this case it will have already been cleared
			},
			expCreation:            true,
			expRegistrationRequest: true,
		},
		{
			name: "valid creds",
			in: func(t *testing.T, w *Worker) {
				// Store the authorized creds
				require.NoError(t, initNodeCreds.Store(ctx, w.WorkerAuthStorage))
			},
		},
		{
			name: "existing but not validated",
			in: func(t *testing.T, w *Worker) {
				creds := proto.Clone(initNodeCreds).(*types.NodeCredentials)
				creds.CertificateBundles = nil
				creds.RegistrationNonce = nonce
				require.NoError(t, creds.Store(ctx, w.WorkerAuthStorage))
			},
			expKeyId:               initKeyId,
			expRegistrationRequest: true,
		},
		{
			name: "existing and outside cert times", // Note that cert from next CA will already not be valid
			in: func(t *testing.T, w *Worker) {
				creds := proto.Clone(initNodeCreds).(*types.NodeCredentials)
				creds.CertificateBundles[0].CertificateNotBefore = timestamppb.New(time.Time{})
				creds.CertificateBundles[0].CertificateNotAfter = timestamppb.New(time.Time{})
				require.NoError(t, creds.Store(ctx, w.WorkerAuthStorage))
			},
			expCreation:            true,
			expRegistrationRequest: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tw := NewTestWorker(t, &TestWorkerOpts{
				WorkerAuthStoragePath: tmpDir,
				DisableAutoStart:      true,
			})
			t.Cleanup(tw.Shutdown)

			// Always clear out storage that was there before, ignore errors
			_ = tw.Worker().WorkerAuthStorage.Remove(ctx, &types.NodeCredentials{Id: string(nodeenrollment.CurrentId)})

			// Run node credentials modification
			tt.in(t, tw.Worker())

			// Start up to run logic
			require.NoError(t, tw.Worker().Start())

			// Validate state
			if tt.expKeyId != "" {
				assert.Equal(t, tt.expKeyId, tw.Worker().WorkerAuthCurrentKeyId)
			} else {
				if tt.expCreation {
					assert.NotEmpty(t, tw.Worker().WorkerAuthCurrentKeyId)
				} else {
					assert.Empty(t, tw.Worker().WorkerAuthCurrentKeyId)
				}
			}
			if tt.expRegistrationRequest {
				assert.NotEmpty(t, tw.Worker().WorkerAuthRegistrationRequest)
			} else {
				assert.Empty(t, tw.Worker().WorkerAuthRegistrationRequest)
			}
		})
	}
}
