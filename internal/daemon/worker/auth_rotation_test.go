package worker_test

import (
	"testing"

	"github.com/hashicorp/boundary/internal/cmd/config"
	"github.com/hashicorp/boundary/internal/daemon/controller"
	"github.com/hashicorp/boundary/internal/daemon/worker"
	"github.com/hashicorp/boundary/internal/servers"
	"github.com/hashicorp/boundary/internal/servers/store"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/nodeenrollment/rotation"
	"github.com/hashicorp/nodeenrollment/types"
	"github.com/mr-tron/base58"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

// TestRotationTicking ensures that we see new credential information for a
// worker on both the controller side and worker side in a periodic fashion. It
// does not test the function that performs most of the actual rotation logic;
// that is in a separate test.
func TestRotationTicking(t *testing.T) {
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

	w := worker.NewTestWorker(t, &worker.TestWorkerOpts{
		InitialControllers: c.ClusterAddrs(),
		Logger:             logger.Named("worker"),
	})
	t.Cleanup(w.Shutdown)

	// Get a servers repo and worker auth repo
	serversRepo, err := c.Controller().ServersRepoFn()
	require.NoError(err)
	workerAuthRepo, err := c.Controller().WorkerAuthRepoStorageFn()
	require.NoError(err)

	// Ensure roots exist
	_, err = rotation.RotateRootCertificates(c.Context(), workerAuthRepo)
	require.NoError(err)

	// Verify that there are no nodes authorized yet
	workers, err := workerAuthRepo.List(c.Context(), (*types.NodeInformation)(nil))
	require.NoError(err)
	assert.Len(workers, 0)

	// Perform initial authentication of worker to controller
	reqBytes, err := base58.FastBase58Decoding(w.Worker().WorkerAuthRegistrationRequest)
	require.NoError(err)

	// Decode the proto into the request
	req := new(types.FetchNodeCredentialsRequest)
	require.NoError(proto.Unmarshal(reqBytes, req))

	_, err = serversRepo.CreateWorker(c.Context(), &servers.Worker{
		Worker: &store.Worker{
			ScopeId: scope.Global.String(),
		},
	}, servers.WithFetchNodeCredentialsRequest(req))
	require.NoError(err)

	// Verify we see one authorized worker now and hold on to its public id
	workers, err = workerAuthRepo.List(c.Context(), (*types.NodeInformation)(nil))
	require.NoError(err)
	assert.Len(workers, 1)
}
