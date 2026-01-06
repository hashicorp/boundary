// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package workers_test

import (
	"context"
	"crypto/rand"
	"testing"

	"github.com/hashicorp/boundary/api/workers"
	"github.com/hashicorp/boundary/internal/daemon/controller"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/server"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/nodeenrollment/rotation"
	"github.com/hashicorp/nodeenrollment/storage/file"
	"github.com/hashicorp/nodeenrollment/types"
	"github.com/mr-tron/base58"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestWorkerTagsASD(t *testing.T) {
	ctx := context.Background()
	assert, require := assert.New(t), require.New(t)
	tc := controller.NewTestController(t, nil)
	defer tc.Shutdown()

	client := tc.Client()
	token := tc.Token()
	client.SetToken(token.Token)
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)

	// Ensures the global scope contains a valid root key
	err := kmsCache.CreateKeys(ctx, scope.Global.String(), kms.WithRandomReader(rand.Reader))
	require.NoError(err)
	wrapper, err = kmsCache.GetWrapper(ctx, scope.Global.String(), kms.KeyPurposeDatabase)
	require.NoError(err)
	require.NotNil(wrapper)

	// Set up certs on the controller
	rootStorage, err := server.NewRepositoryStorage(ctx, rw, rw, kmsCache)
	require.NoError(err)
	_, err = rotation.RotateRootCertificates(ctx, rootStorage)
	require.NoError(err)

	// Emulate creating credentials on a worker
	fileStorage, err := file.New(ctx)
	require.NoError(err)
	nodeCreds, err := types.NewNodeCredentials(ctx, fileStorage)
	require.NoError(err)
	fetchReq, err := nodeCreds.CreateFetchNodeCredentialsRequest(ctx)
	require.NoError(err)

	// Create a workerAuth request to be passed to the workerClient
	reqBytes, err := proto.Marshal(fetchReq)
	require.NoError(err)
	registrationReq := base58.FastBase58Encoding(reqBytes)

	workerClient := workers.NewClient(client)

	wcr, err := workerClient.CreateWorkerLed(tc.Context(), registrationReq, scope.Global.String())
	require.NoError(err)

	inputTags := map[string][]string{"key": {"value"}}
	wcr, err = workerClient.AddWorkerTags(tc.Context(), wcr.Item.Id, wcr.Item.Version, inputTags)
	require.NoError(err)
	require.NotNil(wcr)
	for k, v := range wcr.Item.ApiTags {
		for expK, expV := range inputTags {
			assert.Equal(k, expK)
			assert.ElementsMatch(v, expV)
		}
	}

	inputTags = map[string][]string{"key2": {"value2", "value3"}}
	wcr, err = workerClient.SetWorkerTags(tc.Context(), wcr.Item.Id, wcr.Item.Version, inputTags)
	require.NoError(err)
	require.NotNil(wcr)
	for k, v := range wcr.Item.ApiTags {
		for expK, expV := range inputTags {
			assert.Equal(k, expK)
			assert.ElementsMatch(v, expV)
		}
	}

	inputTags = map[string][]string{"key2": {"value3"}}
	wcr, err = workerClient.RemoveWorkerTags(tc.Context(), wcr.Item.Id, wcr.Item.Version, inputTags)
	require.NoError(err)
	require.NotNil(wcr)
	for k, v := range wcr.Item.ApiTags {
		for expK := range inputTags {
			assert.Equal(k, expK)
			assert.ElementsMatch(v, []string{"value2"})
		}
	}

	wcr, err = workerClient.SetWorkerTags(tc.Context(), wcr.Item.Id, wcr.Item.Version, nil)
	require.NoError(err)
	require.NotNil(wcr)
	assert.Empty(wcr.Item.ApiTags)

	// Test adding the same tag twice
	inputTags = map[string][]string{"keykey": {"valval"}}
	wcr, err = workerClient.AddWorkerTags(tc.Context(), wcr.Item.Id, wcr.Item.Version, inputTags)
	require.NoError(err)
	require.NotNil(wcr)
	for k, v := range wcr.Item.ApiTags {
		for expK, expV := range inputTags {
			assert.Equal(k, expK)
			assert.ElementsMatch(v, expV)
		}
	}
	inputTags = map[string][]string{"keykey": {"valval"}}
	ewcr, err := workerClient.AddWorkerTags(tc.Context(), wcr.Item.Id, wcr.Item.Version, inputTags)
	require.Error(err)
	require.Nil(ewcr)

	inputTags = map[string][]string{"invalid_tag": nil}
	ewcr, err = workerClient.SetWorkerTags(tc.Context(), wcr.Item.Id, wcr.Item.Version, inputTags)
	require.Error(err)
	require.Nil(ewcr)

	inputTags = map[string][]string{"non_extant": {"tag"}}
	ewcr, err = workerClient.RemoveWorkerTags(tc.Context(), wcr.Item.Id, wcr.Item.Version, inputTags)
	require.Error(err)
	require.Nil(ewcr)
}
