// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"strings"
	"testing"
	"time"

	"github.com/fatih/structs"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/server/store"
	"github.com/hashicorp/boundary/internal/types/scope"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/registration"
	"github.com/hashicorp/nodeenrollment/rotation"
	"github.com/hashicorp/nodeenrollment/storage/file"
	"github.com/hashicorp/nodeenrollment/storage/inmem"
	"github.com/hashicorp/nodeenrollment/types"
	"github.com/mitchellh/mapstructure"
	"github.com/mr-tron/base58"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
)

// Test RootCertificate storage
func TestStoreRootCertificates(t *testing.T) {
	require, assert := require.New(t), assert.New(t)
	ctx := context.Background()
	wrapper := db.TestWrapper(t)
	conn, _ := db.TestSetup(t, "postgres")
	kmsCache := kms.TestKms(t, conn, wrapper)
	// Ensures the global scope contains a valid root key
	err := kmsCache.CreateKeys(context.Background(), scope.Global.String(), kms.WithRandomReader(rand.Reader))
	require.NoError(err)
	wrapper, err = kmsCache.GetWrapper(context.Background(), scope.Global.String(), kms.KeyPurposeDatabase)
	require.NoError(err)
	require.NotNil(wrapper)

	rw := db.New(conn)
	workerAuthRepo, err := NewRepositoryStorage(ctx, rw, rw, kmsCache)
	require.NoError(err)

	// Fail to find root certificates prior to rotation/ creation
	noCertAuth := &types.RootCertificates{Id: CaId}
	err = workerAuthRepo.Load(ctx, noCertAuth)
	require.Error(err)
	rootIds, err := workerAuthRepo.List(ctx, (*types.RootCertificate)(nil))
	require.NoError(err)
	assert.Len(rootIds, 0)

	// Rotate will generate and store next and current, as we have none
	roots, err := rotation.RotateRootCertificates(ctx, workerAuthRepo)
	require.NoError(err)
	rootIds, err = workerAuthRepo.List(ctx, (*types.RootCertificate)(nil))
	require.NoError(err)
	assert.Len(rootIds, 2)

	// Load stored roots
	certAuthority := &types.RootCertificates{Id: CaId}
	err = workerAuthRepo.Load(ctx, certAuthority)
	require.NoError(err)
	require.NotNil(certAuthority.GetNext())
	require.NotNil(certAuthority.GetCurrent())

	// Read the next cert and validate the stored values are valid after encrypt and decrypt
	assert.Equal(roots.Next.PrivateKeyPkcs8, certAuthority.Next.PrivateKeyPkcs8)

	// Read the current cert and validate the stored values are valid after encrypt and decrypt
	assert.Equal(roots.Current.PrivateKeyPkcs8, certAuthority.Current.PrivateKeyPkcs8)

	// Fail to find root certificates under bogus id
	bogusCertAuth := &types.RootCertificates{Id: "bogus"}
	err = workerAuthRepo.Load(ctx, bogusCertAuth)
	require.Error(err)
}

func TestStoreCertAuthorityVersioning(t *testing.T) {
	require, assert := require.New(t), assert.New(t)
	ctx := context.Background()
	wrapper := db.TestWrapper(t)
	conn, _ := db.TestSetup(t, "postgres")
	kmsCache := kms.TestKms(t, conn, wrapper)
	// Ensures the global scope contains a valid root key
	err := kmsCache.CreateKeys(context.Background(), scope.Global.String(), kms.WithRandomReader(rand.Reader))
	require.NoError(err)
	wrapper, err = kmsCache.GetWrapper(context.Background(), scope.Global.String(), kms.KeyPurposeDatabase)
	require.NoError(err)
	require.NotNil(wrapper)

	rw := db.New(conn)
	workerAuthRepo, err := NewRepositoryStorage(ctx, rw, rw, kmsCache)
	require.NoError(err)

	// Store CA and check that initial version updates
	roots, err := rotation.RotateRootCertificates(ctx, workerAuthRepo)
	require.NoError(err)

	cAuth2 := &types.RootCertificates{Id: CaId}
	err = workerAuthRepo.Load(ctx, cAuth2)
	require.NoError(err)
	var result2 rootCertificatesVersion
	err = mapstructure.Decode(cAuth2.State.AsMap(), &result2)
	require.NoError(err)
	assert.Equal(uint32(2), result2.Version)

	// Store CA with old version, expect error
	badVersion := &rootCertificatesVersion{Version: uint32(1)}
	s := structs.New(badVersion)
	s.TagName = "mapstructure"
	badState, err := structpb.NewStruct(s.Map())
	require.NoError(err)
	newRoots2 := &types.RootCertificates{
		Id:      CaId,
		Next:    roots.Next,
		Current: roots.Current,
	}
	newRoots2.State = badState
	err = workerAuthRepo.Store(ctx, newRoots2)
	require.Error(err)

	// Remove CA, expect updated version
	cAuthRemove := &types.RootCertificates{Id: CaId}
	removeVersion := &rootCertificatesVersion{Version: uint32(2)}
	s = structs.New(removeVersion)
	s.TagName = "mapstructure"
	removeState, err := structpb.NewStruct(s.Map())
	require.NoError(err)
	cAuthRemove.State = removeState
	err = workerAuthRepo.Remove(ctx, cAuthRemove)
	require.NoError(err)
}

// Test WorkerAuth storage
func TestStoreWorkerAuth(t *testing.T) {
	require, assert := require.New(t), assert.New(t)
	ctx := context.Background()
	rootWrapper := db.TestWrapper(t)
	conn, _ := db.TestSetup(t, "postgres")
	kmsCache := kms.TestKms(t, conn, rootWrapper)

	// Ensures the global scope contains a valid root key
	require.NoError(kmsCache.CreateKeys(context.Background(), scope.Global.String(), kms.WithRandomReader(rand.Reader)))

	worker := TestPkiWorker(t, conn, rootWrapper)

	rw := db.New(conn)
	rootStorage, err := NewRepositoryStorage(ctx, rw, rw, kmsCache)
	require.NoError(err)

	_, err = rotation.RotateRootCertificates(ctx, rootStorage)
	require.NoError(err)

	// Create struct to pass in with workerId that will be passed along to storage
	state, err := AttachWorkerIdToState(ctx, worker.PublicId)
	require.NoError(err)

	// This happens on the worker
	fileStorage, err := file.New(ctx)
	require.NoError(err)
	nodeCreds, err := types.NewNodeCredentials(ctx, fileStorage)
	require.NoError(err)
	// Create request using worker id
	fetchReq, err := nodeCreds.CreateFetchNodeCredentialsRequest(ctx)
	require.NoError(err)
	keyId, err := nodeenrollment.KeyIdFromPkix(nodeCreds.CertificatePublicKeyPkix)
	require.NoError(err)
	privKey, err := ecdh.X25519().NewPrivateKey(nodeCreds.EncryptionPrivateKeyBytes)
	require.NoError(err)
	nodePubKey := privKey.PublicKey().Bytes()

	// Add in node information to storage so we have a key to use
	nodeInfo := &types.NodeInformation{
		Id:                       keyId,
		CertificatePublicKeyPkix: nodeCreds.CertificatePublicKeyPkix,
		CertificatePublicKeyType: nodeCreds.CertificatePrivateKeyType,
		EncryptionPublicKeyBytes: nodePubKey,
		EncryptionPublicKeyType:  nodeCreds.EncryptionPrivateKeyType,
		RegistrationNonce:        nodeCreds.RegistrationNonce,
		State:                    state,
	}

	// Create storage for authentication and pass it the worker
	storage, err := NewRepositoryStorage(ctx, rw, rw, kmsCache)
	require.NoError(err)

	// Look for node info and expect to find nothing
	nodeLookup := &types.NodeInformation{
		Id: keyId,
	}
	err = storage.Load(ctx, nodeLookup)
	assert.Equal(err, nodeenrollment.ErrNotFound)

	// The AuthorizeNode request will result in a WorkerAuth record being stored
	_, err = registration.AuthorizeNode(ctx, storage, fetchReq, nodeenrollment.WithState(state))
	require.NoError(err)

	// We should now look for a node information value in storage and validate that it's populated
	nodeInfos, err := storage.List(ctx, (*types.NodeInformation)(nil))
	require.NoError(err)
	require.NotEmpty(nodeInfos)
	assert.Len(nodeInfos, 1)

	// Validate the stored fields match those from the worker
	err = storage.Load(ctx, nodeLookup)
	require.NoError(err)
	assert.NotEmpty(nodeLookup)
	assert.Equal(nodeInfo.EncryptionPublicKeyBytes, nodeLookup.EncryptionPublicKeyBytes)
	assert.Equal(nodeInfo.RegistrationNonce, nodeLookup.RegistrationNonce)
	assert.Equal(nodeInfo.CertificatePublicKeyPkix, nodeLookup.CertificatePublicKeyPkix)
	assert.Equal(nodeInfo.State.AsMap(), nodeLookup.State.AsMap())
	assert.Empty(nodeInfo.PreviousEncryptionKey)

	// Validate that we can find the workerAuth set and key identifier
	workerAuthSet, err := storage.FindWorkerAuthByWorkerId(ctx, worker.PublicId)
	assert.NoError(err)
	assert.Equal(workerAuthSet.Current.WorkerKeyIdentifier, keyId)

	// Remove node
	err = storage.Remove(ctx, nodeLookup)
	require.NoError(err)
	err = storage.Load(ctx, nodeLookup)
	require.Error(err)
}

func TestStoreServerLedActivationToken(t *testing.T) {
	require, assert := require.New(t), assert.New(t)
	ctx := context.Background()
	rootWrapper := db.TestWrapper(t)
	conn, _ := db.TestSetup(t, "postgres")
	kmsCache := kms.TestKms(t, conn, rootWrapper)

	// Ensure the global scope contains a valid root key
	require.NoError(kmsCache.CreateKeys(context.Background(), scope.Global.String(), kms.WithRandomReader(rand.Reader)))

	rw := db.New(conn)
	rootStorage, err := NewRepositoryStorage(ctx, rw, rw, kmsCache)
	require.NoError(err)

	_, err = rotation.RotateRootCertificates(ctx, rootStorage)
	require.NoError(err)

	repo, err := NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(err)
	worker, err := repo.CreateWorker(ctx, &Worker{Worker: &store.Worker{ScopeId: scope.Global.String()}}, WithCreateControllerLedActivationToken(true))
	require.NoError(err)
	require.NotEmpty(worker.ControllerGeneratedActivationToken)

	// We should now look for an activation token value in storage using the
	// lookup function and validate that it's populated
	tokenNonce := new(types.ServerLedActivationTokenNonce)
	marshaledNonce, err := base58.FastBase58Decoding(strings.TrimPrefix(worker.ControllerGeneratedActivationToken, nodeenrollment.ServerLedActivationTokenPrefix))
	require.NoError(err)
	require.NoError(proto.Unmarshal(marshaledNonce, tokenNonce))
	hm := hmac.New(sha256.New, tokenNonce.HmacKeyBytes)
	idBytes := hm.Sum(tokenNonce.Nonce)
	actToken := &types.ServerLedActivationToken{
		Id: base58.FastBase58Encoding(idBytes),
	}
	require.NoError(rootStorage.Load(ctx, actToken))
	require.NotNil(actToken.CreationTime)
	assert.False(actToken.CreationTime.AsTime().IsZero())
	assert.Less(time.Until(actToken.CreationTime.AsTime()), time.Duration(0))

	require.NoError(rootStorage.Remove(ctx, actToken))
	require.Error(rootStorage.Load(ctx, actToken))
}

func TestUnsupportedMessages(t *testing.T) {
	require := require.New(t)
	ctx := context.Background()
	wrapper := db.TestWrapper(t)
	conn, _ := db.TestSetup(t, "postgres")
	kmsCache := kms.TestKms(t, conn, wrapper)

	rw := db.New(conn)
	storage, err := NewRepositoryStorage(ctx, rw, rw, kmsCache)
	require.NoError(err)

	err = storage.Store(ctx, &types.NodeCredentials{})
	require.Error(err)

	err = storage.Load(ctx, &types.NodeCredentials{Id: "bogus"})
	require.Error(err)

	_, err = storage.List(ctx, (*types.NodeCredentials)(nil))
	require.Error(err)

	err = storage.Remove(ctx, &types.NodeCredentials{Id: "bogus"})
	require.Error(err)
}

func TestStoreNodeInformationTx(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()

	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)

	testWrapper := db.TestWrapper(t)
	testKeyId, err := testWrapper.KeyId(testCtx)
	require.NoError(t, err)

	kmsCache := kms.TestKms(t, conn, testWrapper)
	// Ensures the global scope contains a valid root key
	require.NoError(t, kmsCache.CreateKeys(context.Background(), scope.Global.String(), kms.WithRandomReader(rand.Reader)))

	testRootStorage, err := NewRepositoryStorage(testCtx, rw, rw, kmsCache)
	require.NoError(t, err)

	_, err = rotation.RotateRootCertificates(testCtx, testRootStorage)
	require.NoError(t, err)

	// Create struct to pass in with workerId that will be passed along to
	// storage
	testWorker := TestPkiWorker(t, conn, testWrapper)

	testState, err := AttachWorkerIdToState(testCtx, testWorker.PublicId)
	require.NoError(t, err)

	testNodeInfoFn := func() *types.NodeInformation {
		// This happens on the worker
		storage, err := inmem.New(testCtx)
		require.NoError(t, err)
		nodeCreds, err := types.NewNodeCredentials(testCtx, storage)
		require.NoError(t, err)

		privKey, err := ecdh.X25519().NewPrivateKey(nodeCreds.EncryptionPrivateKeyBytes)
		require.NoError(t, err)
		nodePubKey := privKey.PublicKey().Bytes()
		// Add in node information to storage so we have a key to use
		nodeInfo := &types.NodeInformation{
			Id:                              testKeyId,
			CertificatePublicKeyPkix:        nodeCreds.CertificatePublicKeyPkix,
			CertificatePublicKeyType:        nodeCreds.CertificatePrivateKeyType,
			EncryptionPublicKeyBytes:        nodePubKey,
			EncryptionPublicKeyType:         nodeCreds.EncryptionPrivateKeyType,
			ServerEncryptionPrivateKeyBytes: []byte("whatever"),
			RegistrationNonce:               nodeCreds.RegistrationNonce,
			State:                           testState,
		}
		return nodeInfo
	}

	// For swapping out key ID for wrapping registration flow
	wrappingRegFlowStorage, err := inmem.New(testCtx)
	require.NoError(t, err)
	wrappingRegFlowNodeCreds, err := types.NewNodeCredentials(testCtx, wrappingRegFlowStorage)
	require.NoError(t, err)
	wrappingRegFlowNodeInfoFn := func() *types.NodeInformation {
		ni := testNodeInfoFn()
		wci, err := structpb.NewStruct(map[string]any{
			"name":             "regflow-worker-name",
			"description":      "regflow-worker-description",
			"boundary_version": "0.13.0",
		})
		require.NoError(t, err)
		ni.WrappingRegistrationFlowInfo = &types.WrappingRegistrationFlowInfo{
			Nonce:                     ni.RegistrationNonce,
			CertificatePublicKeyPkix:  ni.CertificatePublicKeyPkix,
			ApplicationSpecificParams: wci,
		}
		return ni
	}

	tests := []struct {
		name            string
		reader          db.Reader
		writer          db.Writer
		scope           string
		kms             *kms.Kms
		node            *types.NodeInformation
		wantErr         bool
		wantErrIs       errors.Code
		wantErrContains string
	}{
		{
			name:            "missing-writer",
			reader:          rw,
			scope:           scope.Global.String(),
			kms:             kmsCache,
			node:            testNodeInfoFn(),
			wantErr:         true,
			wantErrIs:       errors.InvalidParameter,
			wantErrContains: "missing writer",
		},
		{
			name:            "missing-reader",
			writer:          rw,
			scope:           scope.Global.String(),
			kms:             kmsCache,
			node:            testNodeInfoFn(),
			wantErr:         true,
			wantErrIs:       errors.InvalidParameter,
			wantErrContains: "missing reader",
		},
		{
			name:            "missing-scope",
			reader:          rw,
			writer:          rw,
			kms:             kmsCache,
			node:            testNodeInfoFn(),
			wantErr:         true,
			wantErrIs:       errors.InvalidParameter,
			wantErrContains: "missing scope",
		},
		{
			name:            "missing-kms",
			reader:          rw,
			writer:          rw,
			scope:           scope.Global.String(),
			node:            testNodeInfoFn(),
			wantErr:         true,
			wantErrIs:       errors.InvalidParameter,
			wantErrContains: "missing kms",
		},
		{
			name:            "missing-node",
			reader:          rw,
			writer:          rw,
			scope:           scope.Global.String(),
			kms:             kmsCache,
			wantErr:         true,
			wantErrIs:       errors.InvalidParameter,
			wantErrContains: "missing NodeInformation",
		},
		{
			name:            "create-error-no-db",
			reader:          rw,
			scope:           scope.Global.String(),
			writer:          &db.Db{},
			kms:             kmsCache,
			node:            testNodeInfoFn(),
			wantErr:         true,
			wantErrContains: "db.Create",
		},
		{
			name:   "create-error-validation",
			reader: rw,
			writer: rw,
			scope:  scope.Global.String(),
			kms:    kmsCache,
			node: func() *types.NodeInformation {
				ni := testNodeInfoFn()
				ni.State = nil
				return ni
			}(),
			wantErr:         true,
			wantErrContains: "missing WorkerId",
		},
		{
			name:   "wrapflow-no-name",
			reader: rw,
			writer: rw,
			scope:  scope.Global.String(),
			kms:    kmsCache,
			node: func() *types.NodeInformation {
				ni := wrappingRegFlowNodeInfoFn()
				ni.WrappingRegistrationFlowInfo.ApplicationSpecificParams.Fields["name"] = nil
				ni.CertificatePublicKeyPkix = wrappingRegFlowNodeCreds.CertificatePublicKeyPkix
				keyId, err := nodeenrollment.KeyIdFromPkix(ni.CertificatePublicKeyPkix)
				require.NoError(t, err)
				ni.Id = keyId
				return ni
			}(),
			wantErr:         true,
			wantErrContains: "in wrapping registration flow but worker name not provided",
		},
		{
			name:   "wrapflow-no-version",
			reader: rw,
			writer: rw,
			scope:  scope.Global.String(),
			kms:    kmsCache,
			node: func() *types.NodeInformation {
				ni := wrappingRegFlowNodeInfoFn()
				ni.WrappingRegistrationFlowInfo.ApplicationSpecificParams.Fields["boundary_version"] = nil
				ni.CertificatePublicKeyPkix = wrappingRegFlowNodeCreds.CertificatePublicKeyPkix
				keyId, err := nodeenrollment.KeyIdFromPkix(ni.CertificatePublicKeyPkix)
				require.NoError(t, err)
				ni.Id = keyId
				return ni
			}(),
			wantErr:         true,
			wantErrContains: "in wrapping registration flow but boundary version not provided",
		},
		{
			name:   "success",
			reader: rw,
			writer: rw,
			scope:  scope.Global.String(),
			kms:    kmsCache,
			node:   testNodeInfoFn(),
		},
		{
			name:   "success-wrapflow",
			reader: rw,
			writer: rw,
			scope:  scope.Global.String(),
			kms:    kmsCache,
			node: func() *types.NodeInformation {
				ni := wrappingRegFlowNodeInfoFn()
				ni.CertificatePublicKeyPkix = wrappingRegFlowNodeCreds.CertificatePublicKeyPkix
				keyId, err := nodeenrollment.KeyIdFromPkix(ni.CertificatePublicKeyPkix)
				require.NoError(t, err)
				ni.Id = keyId
				return ni
			}(),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			err := StoreNodeInformationTx(testCtx, tc.reader, tc.writer, tc.kms, tc.scope, tc.node)
			if tc.wantErr {
				require.Error(err)
				if tc.wantErrIs != errors.Unknown {
					assert.True(errors.Match(errors.T(tc.wantErrIs), err))
				}
				if tc.wantErrContains != "" {
					assert.Contains(err.Error(), tc.wantErrContains)
				}
				return
			}
			require.NoError(err)
		})
	}
}

func TestStoreNodeInformationTx_Twice(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()

	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)

	testWrapper := db.TestWrapper(t)
	testKeyId, err := testWrapper.KeyId(testCtx)
	require.NoError(t, err)

	kmsCache := kms.TestKms(t, conn, testWrapper)
	// Ensures the global scope contains a valid root key
	require.NoError(t, kmsCache.CreateKeys(context.Background(), scope.Global.String(), kms.WithRandomReader(rand.Reader)))

	testRootStorage, err := NewRepositoryStorage(testCtx, rw, rw, kmsCache)
	require.NoError(t, err)

	_, err = rotation.RotateRootCertificates(testCtx, testRootStorage)
	require.NoError(t, err)

	// Create struct to pass in with workerId that will be passed along to
	// storage
	testWorker := TestPkiWorker(t, conn, testWrapper)

	testState, err := AttachWorkerIdToState(testCtx, testWorker.PublicId)
	require.NoError(t, err)

	testNodeInfoFn := func() *types.NodeInformation {
		// This happens on the worker
		storage, err := inmem.New(testCtx)
		require.NoError(t, err)
		nodeCreds, err := types.NewNodeCredentials(testCtx, storage)
		require.NoError(t, err)

		privKey, err := ecdh.X25519().NewPrivateKey(nodeCreds.EncryptionPrivateKeyBytes)
		require.NoError(t, err)
		nodePubKey := privKey.PublicKey().Bytes()
		// Add in node information to storage so we have a key to use
		nodeInfo := &types.NodeInformation{
			Id:                              testKeyId,
			CertificatePublicKeyPkix:        nodeCreds.CertificatePublicKeyPkix,
			CertificatePublicKeyType:        nodeCreds.CertificatePrivateKeyType,
			EncryptionPublicKeyBytes:        nodePubKey,
			EncryptionPublicKeyType:         nodeCreds.EncryptionPrivateKeyType,
			ServerEncryptionPrivateKeyBytes: []byte("whatever"),
			RegistrationNonce:               nodeCreds.RegistrationNonce,
			State:                           testState,
		}
		return nodeInfo
	}
	testNodeInfoFn2 := func() *types.NodeInformation {
		// This happens on the worker
		storage, err := inmem.New(testCtx)
		require.NoError(t, err)
		nodeCreds, err := types.NewNodeCredentials(testCtx, storage)
		require.NoError(t, err)

		privKey, err := ecdh.X25519().NewPrivateKey(nodeCreds.EncryptionPrivateKeyBytes)
		require.NoError(t, err)
		nodePubKey := privKey.PublicKey().Bytes()
		// Add in node information to storage so we have a key to use
		nodeInfo := &types.NodeInformation{
			Id:                              "fake-secondary-key-id",
			CertificatePublicKeyPkix:        nodeCreds.CertificatePublicKeyPkix,
			CertificatePublicKeyType:        nodeCreds.CertificatePrivateKeyType,
			EncryptionPublicKeyBytes:        nodePubKey,
			EncryptionPublicKeyType:         nodeCreds.EncryptionPrivateKeyType,
			ServerEncryptionPrivateKeyBytes: []byte("whatever"),
			RegistrationNonce:               nodeCreds.RegistrationNonce,
			State:                           testState,
		}
		return nodeInfo
	}

	tests := []struct {
		name                       string
		reader                     db.Reader
		writer                     db.Writer
		scope                      string
		kms                        *kms.Kms
		node                       *types.NodeInformation
		wantErr                    bool
		wantErrIs                  errors.Code
		wantErrContains            string
		secondStoreDifferentNode   bool
		wantSecondStoreErr         bool
		wantSecondStoreErrIs       errors.Code
		wantSecondStoreErrContains string
	}{
		{
			name:                       "duplicate record error",
			reader:                     rw,
			writer:                     rw,
			scope:                      scope.Global.String(),
			kms:                        kmsCache,
			node:                       testNodeInfoFn(),
			wantSecondStoreErr:         true,
			wantSecondStoreErrContains: "duplicate record found",
		},
		{
			// This test will fail because on the second store we change the incoming NodeInformation
			// so that it does not match the already inserted record
			name:                       "fail-store-twice-different-node-info",
			reader:                     rw,
			writer:                     rw,
			scope:                      scope.Global.String(),
			kms:                        kmsCache,
			node:                       testNodeInfoFn2(),
			secondStoreDifferentNode:   true,
			wantSecondStoreErr:         true,
			wantSecondStoreErrIs:       errors.NotUnique,
			wantSecondStoreErrContains: "server.(WorkerAuthRepositoryStorage).StoreNodeInformationTx: db.Create: duplicate key value violates unique constraint \"worker_auth_authorized_pkey\": unique constraint violation: integrity violation: error #1002",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			err := StoreNodeInformationTx(testCtx, tc.reader, tc.writer, tc.kms, tc.scope, tc.node)
			if tc.wantErr {
				require.Error(err)
				if tc.wantErrIs != errors.Unknown {
					assert.True(errors.Match(errors.T(tc.wantErrIs), err))
				}
				if tc.wantErrContains != "" {
					assert.Contains(err.Error(), tc.wantErrContains)
				}
				return
			}
			require.NoError(err)
			// Try to store the "same" node information twice
			node := tc.node
			if tc.secondStoreDifferentNode {
				storage, err := inmem.New(testCtx)
				require.NoError(err)
				nodeCreds, err := types.NewNodeCredentials(testCtx, storage)
				require.NoError(err)
				node.CertificatePublicKeyPkix = nodeCreds.CertificatePublicKeyPkix
			}
			err = StoreNodeInformationTx(testCtx, tc.reader, tc.writer, tc.kms, tc.scope, node)
			if tc.wantSecondStoreErr {
				require.Error(err)
				if tc.wantSecondStoreErrIs != errors.Unknown {
					assert.True(errors.Match(errors.T(tc.wantSecondStoreErrIs), err))
				}
				if tc.wantSecondStoreErrContains != "" {
					assert.Contains(err.Error(), tc.wantSecondStoreErrContains)
				}
				return
			}
			require.NoError(err)
		})
	}
}

func TestFilterToAuthorizedWorkerKeyIds(t *testing.T) {
	ctx := context.Background()
	rootWrapper := db.TestWrapper(t)
	conn, _ := db.TestSetup(t, "postgres")
	kmsCache := kms.TestKms(t, conn, rootWrapper)

	t.Run("query returns error", func(t *testing.T) {
		conn, mock := db.TestSetupWithMock(t)
		rw := db.New(conn)
		mock.ExpectQuery(`select`).WillReturnError(errors.New(context.Background(), errors.Internal, "test", "lookup-error"))
		brokenRepo, err := NewRepositoryStorage(ctx, rw, rw, kmsCache)
		require.NoError(t, err)
		_, err = brokenRepo.FilterToAuthorizedWorkerKeyIds(ctx, []string{"something"})
		assert.Error(t, err)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	// Ensures the global scope contains a valid root key
	require.NoError(t, kmsCache.CreateKeys(context.Background(), scope.Global.String(), kms.WithRandomReader(rand.Reader)))

	rw := db.New(conn)
	repo, err := NewRepositoryStorage(ctx, rw, rw, kmsCache)
	require.NoError(t, err)
	got, err := repo.FilterToAuthorizedWorkerKeyIds(ctx, []string{})
	require.NoError(t, err)
	assert.Empty(t, got)

	var keyId1 string
	w1 := TestPkiWorker(t, conn, rootWrapper, WithTestPkiWorkerAuthorizedKeyId(&keyId1))
	var keyId2 string
	_ = TestPkiWorker(t, conn, rootWrapper, WithTestPkiWorkerAuthorizedKeyId(&keyId2))

	got, err = repo.FilterToAuthorizedWorkerKeyIds(ctx, []string{"not-found-key-id", keyId1})
	assert.NoError(t, err)
	assert.Equal(t, []string{keyId1}, got)

	got, err = repo.FilterToAuthorizedWorkerKeyIds(ctx, []string{keyId2, "not-found-key-id"})
	assert.NoError(t, err)
	assert.Equal(t, []string{keyId2}, got)

	got, err = repo.FilterToAuthorizedWorkerKeyIds(ctx, []string{keyId1, keyId2, "unfound-key"})
	assert.NoError(t, err)
	assert.ElementsMatch(t, []string{keyId1, keyId2}, got)

	workerRepo, err := NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(t, err)
	_, err = workerRepo.DeleteWorker(ctx, w1.GetPublicId())
	require.NoError(t, err)

	got, err = repo.FilterToAuthorizedWorkerKeyIds(ctx, []string{keyId1, keyId2, "unfound-key"})
	assert.NoError(t, err)
	assert.Equal(t, []string{keyId2}, got)
}

func TestSplitBrain(t *testing.T) {
	ctx := context.Background()
	require := require.New(t)

	wrapper := db.TestWrapper(t)
	conn, _ := db.TestSetup(t, "postgres")
	kmsCache := kms.TestKms(t, conn, wrapper)
	// Ensures the global scope contains a valid root key
	err := kmsCache.CreateKeys(context.Background(), scope.Global.String(), kms.WithRandomReader(rand.Reader))
	require.NoError(err)
	wrapper, err = kmsCache.GetWrapper(context.Background(), scope.Global.String(), kms.KeyPurposeDatabase)
	require.NoError(err)
	require.NotNil(t, wrapper)

	rw := db.New(conn)

	serversRepo, err := NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(err)

	require.NoError(err)
	wrk := NewWorker(scope.Global.String())
	wrk, err = serversRepo.CreateWorker(ctx, wrk)
	require.NoError(err)
	require.NotNil(wrk)

	controllerStorage, err := NewRepositoryStorage(ctx, rw, rw, kmsCache)
	require.NoError(err)

	_, err = rotation.RotateRootCertificates(ctx, controllerStorage)
	require.NoError(err)

	// Create struct to pass in with workerId that will be passed along to storage
	state, err := AttachWorkerIdToState(ctx, wrk.PublicId)
	require.NoError(err)

	// This happens on the worker
	workerStorage, err := file.New(ctx)
	require.NoError(err)
	initCreds, err := types.NewNodeCredentials(ctx, workerStorage)
	require.NoError(err)
	// Create request using worker id
	fetchReq, err := initCreds.CreateFetchNodeCredentialsRequest(ctx)
	require.NoError(err)
	registeredNode, err := registration.AuthorizeNode(ctx, controllerStorage, fetchReq, nodeenrollment.WithState(state))
	require.NoError(err)
	require.NotNil(registeredNode)

	fetchResp, err := registration.FetchNodeCredentials(ctx, controllerStorage, fetchReq)
	require.NoError(err)
	initCreds, err = initCreds.HandleFetchNodeCredentialsResponse(ctx, workerStorage, fetchResp)
	require.NoError(err)

	// Simulate the auth rotation
	// Worker side ----------------------------------
	newCreds, err := types.NewNodeCredentials(ctx, workerStorage, nodeenrollment.WithSkipStorage(true))
	require.NoError(err)

	newCreds.PreviousCertificatePublicKeyPkix = initCreds.CertificatePublicKeyPkix
	fetchReq, err = newCreds.CreateFetchNodeCredentialsRequest(ctx)
	require.NoError(err)

	encFetchReq, err := nodeenrollment.EncryptMessage(ctx, fetchReq, initCreds)
	require.NoError(err)

	controllerReq := &types.RotateNodeCredentialsRequest{
		CertificatePublicKeyPkix:             initCreds.CertificatePublicKeyPkix,
		EncryptedFetchNodeCredentialsRequest: encFetchReq,
	}

	// Send request to controller
	// Controller side ------------------------------
	resp, err := rotation.RotateNodeCredentials(ctx, controllerStorage, controllerReq)
	require.NoError(err)

	// Send response to worker
	// Worker side ----------------------------------
	// Simulate response going missing
	_ = resp

	// Now simulate the subsequent auth rotation attempt
	newNewCreds, err := types.NewNodeCredentials(ctx, workerStorage, nodeenrollment.WithSkipStorage(true))
	require.NoError(err)
	require.NotEqual(t, newNewCreds.CertificatePublicKeyPkix, newCreds.CertificatePublicKeyPkix)

	newNewCreds.PreviousCertificatePublicKeyPkix = initCreds.CertificatePublicKeyPkix
	fetchReq, err = newNewCreds.CreateFetchNodeCredentialsRequest(ctx)
	require.NoError(err)

	encFetchReq, err = nodeenrollment.EncryptMessage(ctx, fetchReq, initCreds)
	require.NoError(err)

	controllerReq = &types.RotateNodeCredentialsRequest{
		CertificatePublicKeyPkix:             initCreds.CertificatePublicKeyPkix,
		EncryptedFetchNodeCredentialsRequest: encFetchReq,
	}

	// Send request to controller
	// Controller side ------------------------------
	// Split brain would fail this, as it used the wrong creds for decryption
	_, err = rotation.RotateNodeCredentials(ctx, controllerStorage, controllerReq)
	require.NoError(err)

	// Ensure new key has been stored
	keyId, err := nodeenrollment.KeyIdFromPkix(newNewCreds.CertificatePublicKeyPkix)
	require.NoError(err)
	_, err = types.LoadNodeInformation(ctx, controllerStorage, keyId)
	require.NoError(err)

	// Verify that "split brain" creds have been removed from the DB
	keyId, err = nodeenrollment.KeyIdFromPkix(newCreds.CertificatePublicKeyPkix)
	require.NoError(err)
	_, err = types.LoadNodeInformation(ctx, controllerStorage, keyId)
	require.Error(err)
	require.ErrorIs(err, nodeenrollment.ErrNotFound)

	// Ensure the correct previous key is still stored
	keyId, err = nodeenrollment.KeyIdFromPkix(initCreds.CertificatePublicKeyPkix)
	require.NoError(err)
	_, err = types.LoadNodeInformation(ctx, controllerStorage, keyId)
	require.NoError(err)
}

type mockTestWrapper struct {
	wrapping.Wrapper
	decryptError bool
	encryptError bool
	err          error
	keyId        string
}

func (m *mockTestWrapper) KeyId(context.Context) (string, error) {
	if m.err != nil {
		return "", m.err
	}
	return m.keyId, nil
}

func (m *mockTestWrapper) Encrypt(ctx context.Context, plaintext []byte, options ...wrapping.Option) (*wrapping.BlobInfo, error) {
	if m.err != nil && m.encryptError {
		return nil, m.err
	}
	return &wrapping.BlobInfo{}, nil
}

func (m *mockTestWrapper) Decrypt(ctx context.Context, ciphertext *wrapping.BlobInfo, options ...wrapping.Option) ([]byte, error) {
	if m.err != nil && m.decryptError {
		return nil, m.err
	}
	return []byte("decrypted"), nil
}
