// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package worker_test

import (
	"bytes"
	"sync/atomic"
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
	"google.golang.org/protobuf/proto"
)

// TestRotationTicking ensures that we see new credential information for a
// worker on both the controller side and worker side in a periodic fashion
func TestRotationTicking(t *testing.T) {
	require, assert := require.New(t), assert.New(t)
	logger := hclog.New(&hclog.LoggerOptions{
		Level: hclog.Trace,
	})

	const rotationPeriod = 20 * time.Second

	conf, err := config.DevController()
	require.NoError(err)

	workerAuthDebugEnabled := new(atomic.Bool)
	workerAuthDebugEnabled.Store(true)
	c := controller.NewTestController(t, &controller.TestControllerOpts{
		Config:                          conf,
		Logger:                          logger.Named("controller"),
		WorkerAuthCaCertificateLifetime: rotationPeriod,
		WorkerAuthDebuggingEnabled:      workerAuthDebugEnabled,
	})

	// names should not be set when using pki workers
	wConf, err := config.DevWorker()
	require.NoError(err)
	wConf.Worker.Name = ""
	wConf.Worker.InitialUpstreams = c.ClusterAddrs()
	w := worker.NewTestWorker(t, &worker.TestWorkerOpts{
		InitialUpstreams:           c.ClusterAddrs(),
		Logger:                     logger.Named("worker"),
		Config:                     wConf,
		WorkerAuthDebuggingEnabled: workerAuthDebugEnabled,
	})

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
	newWorker, err := serversRepo.CreateWorker(c.Context(), &server.Worker{
		Worker: &store.Worker{
			ScopeId: scope.Global.String(),
		},
	}, server.WithFetchNodeCredentialsRequest(req))
	require.NoError(err)

	// Wait for a short while; there will be an initial rotation of credentials
	// after authentication
	time.Sleep(rotationPeriod / 2)

	// Verify we see authorized credentials now
	auths, err = workerAuthRepo.List(c.Context(), (*types.NodeInformation)(nil))
	require.NoError(err)
	assert.Len(auths, 2)
	// Fetch creds and store current key
	currNodeCreds, err := types.LoadNodeCredentials(
		w.Context(),
		w.Worker().WorkerAuthStorage,
		nodeenrollment.CurrentId,
		nodeenrollment.WithStorageWrapper(w.Config().WorkerAuthStorageKms),
	)
	require.NoError(err)
	currKey := currNodeCreds.CertificatePublicKeyPkix

	priorKeyId, err := nodeenrollment.KeyIdFromPkix(currKey)
	require.NoError(err)

	// Now we wait and check that we see new values in the DB and different
	// creds on the worker after each rotation period
	rotationCount := 2
	for {
		if rotationCount > 5 {
			break
		}
		nextRotation := w.Worker().AuthRotationNextRotation.Load()
		time.Sleep((*nextRotation).Sub(time.Now()) + 5*time.Second)

		// Verify we see 2- after credentials have rotated, we should see current and previous
		auths, err = workerAuthRepo.List(c.Context(), (*types.NodeInformation)(nil))
		require.NoError(err)
		assert.Len(auths, 2)

		// Fetch creds and compare current key
		currNodeCreds, err := types.LoadNodeCredentials(
			w.Context(),
			w.Worker().WorkerAuthStorage,
			nodeenrollment.CurrentId,
			nodeenrollment.WithStorageWrapper(w.Config().WorkerAuthStorageKms),
		)
		require.NoError(err)
		if bytes.Equal(currKey, currNodeCreds.CertificatePublicKeyPkix) {
			// Load due to parallel tests may mean that we didn't hit rotation
			// yet, loop back to evaluate again
			continue
		}
		assert.NotEqual(currKey, currNodeCreds.CertificatePublicKeyPkix)
		currKey = currNodeCreds.CertificatePublicKeyPkix
		currKeyId, err := nodeenrollment.KeyIdFromPkix(currNodeCreds.CertificatePublicKeyPkix)
		require.NoError(err)
		assert.Equal(currKeyId, w.Worker().WorkerAuthCurrentKeyId.Load())

		// Check that we've got the correct prior encryption key
		previousKeyId, _, err := currNodeCreds.PreviousX25519EncryptionKey()
		require.NoError(err)
		assert.Equal(priorKeyId, previousKeyId)

		// Get workerAuthSet for this worker id and compare keys
		workerAuthSet, err := workerAuthRepo.FindWorkerAuthByWorkerId(c.Context(), newWorker.PublicId)
		require.NoError(err)
		assert.NotNil(workerAuthSet)
		assert.NotNil(workerAuthSet.Previous)
		assert.NotNil(workerAuthSet.Current)
		assert.Equal(workerAuthSet.Current.WorkerKeyIdentifier, currKeyId)
		assert.Equal(workerAuthSet.Previous.WorkerKeyIdentifier, previousKeyId)

		// Save priorKeyId
		priorKeyId = currKeyId

		// Stop and start the client connections to ensure the new credentials
		// are valid; if not, we won't establish a new connection and rotation
		// will fail
		require.NotNil(w.Worker().GrpcClientConn)
		require.NoError(w.Worker().GrpcClientConn.Close())
		require.NoError(w.Worker().StartControllerConnections())
		rotationCount++
	}
}
