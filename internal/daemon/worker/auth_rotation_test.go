// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package worker_test

import (
	"bytes"
	"context"
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
	"github.com/hashicorp/nodeenrollment/registration"
	"github.com/hashicorp/nodeenrollment/rotation"
	nodeeinmem "github.com/hashicorp/nodeenrollment/storage/inmem"
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

	// Make sure we have a failsafe in case the below loop never finds what it's
	// looking for; at expiration the List will fail and we'll hit the Require,
	// exiting
	deadlineCtx, deadlineCtxCancel := context.WithTimeout(c.Context(), 10*time.Minute)
	defer deadlineCtxCancel()

	rotationCount := 2
	for {
		if rotationCount > 5 {
			break
		}
		nextRotation := w.Worker().AuthRotationNextRotation.Load()
		time.Sleep((*nextRotation).Sub(time.Now()) + 5*time.Second)

		// Verify we see 2- after credentials have rotated, we should see current and previous
		auths, err = workerAuthRepo.List(deadlineCtx, (*types.NodeInformation)(nil))
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
		require.NotNil(w.Worker().GrpcClientConn.Load())
		require.NoError(w.Worker().GrpcClientConn.Load().Close())
		require.NoError(w.Worker().StartControllerConnections())
		rotationCount++
	}
}

func TestSplitBrainFault(t *testing.T) {
	ctx := context.Background()
	workerStorage, err := nodeeinmem.New(ctx)
	require.NoError(t, err)
	controllerStorage, err := nodeeinmem.New(ctx)
	require.NoError(t, err)

	// Create initial node creds
	_, err = rotation.RotateRootCertificates(ctx, controllerStorage)
	require.NoError(t, err)
	initCreds, err := types.NewNodeCredentials(ctx, workerStorage)
	require.NoError(t, err)
	req, err := initCreds.CreateFetchNodeCredentialsRequest(ctx)
	require.NoError(t, err)
	_, err = registration.AuthorizeNode(ctx, controllerStorage, req)
	require.NoError(t, err)
	fetchResp, err := registration.FetchNodeCredentials(ctx, controllerStorage, req)
	require.NoError(t, err)
	initCreds, err = initCreds.HandleFetchNodeCredentialsResponse(ctx, workerStorage, fetchResp)
	require.NoError(t, err)

	// Simulate the auth rotation
	// Worker side ----------------------------------
	newCreds, err := types.NewNodeCredentials(ctx, workerStorage, nodeenrollment.WithSkipStorage(true))
	require.NoError(t, err)

	require.NoError(t, newCreds.SetPreviousEncryptionKey(initCreds))
	fetchReq, err := newCreds.CreateFetchNodeCredentialsRequest(ctx)
	require.NoError(t, err)

	encFetchReq, err := nodeenrollment.EncryptMessage(ctx, fetchReq, initCreds)
	require.NoError(t, err)

	controllerReq := &types.RotateNodeCredentialsRequest{
		CertificatePublicKeyPkix:             initCreds.CertificatePublicKeyPkix,
		EncryptedFetchNodeCredentialsRequest: encFetchReq,
	}

	// Send request to controller
	// Controller side ------------------------------

	keyId, err := nodeenrollment.KeyIdFromPkix(controllerReq.CertificatePublicKeyPkix)
	require.NoError(t, err)

	oldNodeInfo, err := types.LoadNodeInformation(ctx, controllerStorage, keyId)
	require.NoError(t, err)

	fetchRequest := new(types.FetchNodeCredentialsRequest)
	require.NoError(t, nodeenrollment.DecryptMessage(ctx, encFetchReq, oldNodeInfo, fetchRequest))

	// Stores the new worker credentials
	_, err = registration.AuthorizeNode(ctx, controllerStorage, fetchRequest)
	require.NoError(t, err)

	fetchResp, err = registration.FetchNodeCredentials(ctx, controllerStorage, fetchRequest)
	require.NoError(t, err)

	encFetchResp, err := nodeenrollment.EncryptMessage(ctx, fetchResp, oldNodeInfo)
	require.NoError(t, err)

	// Send response to worker
	// Worker side ----------------------------------

	// Simulate response going missing
	_ = encFetchResp

	// Now simulate the subsequent auth rotation attempt
	newNewCreds, err := types.NewNodeCredentials(ctx, workerStorage, nodeenrollment.WithSkipStorage(true))
	require.NoError(t, err)

	require.NoError(t, newNewCreds.SetPreviousEncryptionKey(initCreds))
	fetchReq, err = newNewCreds.CreateFetchNodeCredentialsRequest(ctx)
	require.NoError(t, err)

	encFetchReq, err = nodeenrollment.EncryptMessage(ctx, fetchReq, initCreds)
	require.NoError(t, err)

	controllerReq = &types.RotateNodeCredentialsRequest{
		CertificatePublicKeyPkix:             initCreds.CertificatePublicKeyPkix,
		EncryptedFetchNodeCredentialsRequest: encFetchReq,
	}

	// Send request to controller
	// Controller side ------------------------------

	keyId, err = nodeenrollment.KeyIdFromPkix(controllerReq.CertificatePublicKeyPkix)
	require.NoError(t, err)

	oldNodeInfo, err = types.LoadNodeInformation(ctx, controllerStorage, keyId)
	require.NoError(t, err)

	// Expect this to fail
	fetchRequest = new(types.FetchNodeCredentialsRequest)
	require.NoError(t, nodeenrollment.DecryptMessage(ctx, encFetchReq, oldNodeInfo, fetchRequest))

	_, err = registration.AuthorizeNode(ctx, controllerStorage, fetchRequest)
	require.NoError(t, err)

	fetchResp, err = registration.FetchNodeCredentials(ctx, controllerStorage, fetchRequest)
	require.NoError(t, err)

	_, err = nodeenrollment.EncryptMessage(ctx, fetchResp, oldNodeInfo)
	require.NoError(t, err)
}
