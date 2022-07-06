package worker_test

import (
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/cmd/config"
	"github.com/hashicorp/boundary/internal/daemon/controller"
	"github.com/hashicorp/boundary/internal/daemon/worker"
	"github.com/hashicorp/boundary/internal/server"
	"github.com/hashicorp/boundary/internal/server/store"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/types"
	"github.com/mr-tron/base58"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/resolver"
	"google.golang.org/protobuf/proto"
)

// TestRotationTicking ensures that we see new credential information for a
// worker on both the controller side and worker side in a periodic fashion
func TestRotationTicking(t *testing.T) {
	t.Parallel()

	require, assert := require.New(t), assert.New(t)
	logger := hclog.New(&hclog.LoggerOptions{
		Level: hclog.Trace,
	})

	conf, err := config.DevController()
	require.NoError(err)

	c := controller.NewTestController(t, &controller.TestControllerOpts{
		Config: conf,
		Logger: logger.Named("controller"),
	})
	t.Cleanup(c.Shutdown)

	const rotationPeriod = 20 * time.Second

	w := worker.NewTestWorker(t, &worker.TestWorkerOpts{
		InitialUpstreams:   c.ClusterAddrs(),
		Logger:             logger.Named("worker"),
		AuthRotationPeriod: rotationPeriod,
	})
	t.Cleanup(w.Shutdown)

	// Get a server repo and worker auth repo
	serversRepo, err := c.Controller().ServersRepoFn()
	require.NoError(err)
	workerAuthRepo, err := c.Controller().WorkerAuthRepoStorageFn()
	require.NoError(err)

	// Give time for the job to ensure that roots are created and offset us from
	// the rotation period
	time.Sleep(rotationPeriod / 2)

	// Verify that there are no nodes authorized yet
	auths, err := workerAuthRepo.List(c.Context(), (*types.NodeInformation)(nil))
	require.NoError(err)
	assert.Len(auths, 0)

	// Perform initial authentication of worker to controller
	reqBytes, err := base58.FastBase58Decoding(w.Worker().WorkerAuthRegistrationRequest)
	require.NoError(err)

	// Decode the proto into the request and create the worker
	req := new(types.FetchNodeCredentialsRequest)
	require.NoError(proto.Unmarshal(reqBytes, req))
	_, err = serversRepo.CreateWorker(c.Context(), &server.Worker{
		Worker: &store.Worker{
			ScopeId: scope.Global.String(),
		},
	}, server.WithFetchNodeCredentialsRequest(req))
	require.NoError(err)

	// Verify we see one authorized set of credentials now
	auths, err = workerAuthRepo.List(c.Context(), (*types.NodeInformation)(nil))
	require.NoError(err)
	assert.Len(auths, 1)
	// Fetch creds and store current key
	currNodeCreds, err := types.LoadNodeCredentials(w.Context(), w.Worker().WorkerAuthStorage, nodeenrollment.CurrentId)
	require.NoError(err)
	currKey := currNodeCreds.CertificatePublicKeyPkix

	// Now we wait and check that we see new values in the DB and different
	// creds on the worker after each rotation period
	for i := 2; i < 5; i++ {
		time.Sleep(rotationPeriod)

		// Verify we see the expected number, since we aren't expiring any it
		// should be equal to the number of times we did rotations
		auths, err = workerAuthRepo.List(c.Context(), (*types.NodeInformation)(nil))
		require.NoError(err)
		assert.Len(auths, i)

		// Fetch creds and compare current key
		currNodeCreds, err := types.LoadNodeCredentials(w.Context(), w.Worker().WorkerAuthStorage, nodeenrollment.CurrentId)
		require.NoError(err)
		assert.NotEqual(currKey, currNodeCreds.CertificatePublicKeyPkix)
		currKey = currNodeCreds.CertificatePublicKeyPkix
		currKeyId, err := nodeenrollment.KeyIdFromPkix(currNodeCreds.CertificatePublicKeyPkix)
		require.NoError(err)
		assert.Equal(currKeyId, w.Worker().WorkerAuthCurrentKeyId.Load())

		// Stop and start the client connections to ensure the new credentials
		// are valid; if not, we won't establish a new connection and rotation
		// will fail
		w.Worker().Resolver().UpdateState(resolver.State{Addresses: []resolver.Address{}})
		require.NotNil(w.Worker().GrpcClientConn)
		require.NoError(w.Worker().GrpcClientConn.Close())
		require.NoError(w.Worker().StartControllerConnections())
	}
}
