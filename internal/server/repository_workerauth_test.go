package server

import (
	"context"
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
	"github.com/hashicorp/nodeenrollment/types"
	"github.com/mitchellh/mapstructure"
	"github.com/mr-tron/base58"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/curve25519"
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
	nodePubKey, err := curve25519.X25519(nodeCreds.EncryptionPrivateKeyBytes, curve25519.Basepoint)
	require.NoError(err)

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

	// The AuthorizeNode request will result in a WorkerAuth record being stored
	_, err = registration.AuthorizeNode(ctx, storage, fetchReq, nodeenrollment.WithState(state))
	require.NoError(err)

	// We should now look for a node information value in storage and validate that it's populated
	nodeInfos, err := storage.List(ctx, (*types.NodeInformation)(nil))
	require.NoError(err)
	require.NotEmpty(nodeInfos)
	assert.Len(nodeInfos, 1)

	// Validate the stored fields match those from the worker
	nodeLookup := &types.NodeInformation{
		Id: keyId,
	}
	err = storage.Load(ctx, nodeLookup)
	require.NoError(err)
	assert.NotEmpty(nodeLookup)
	assert.Equal(nodeInfo.EncryptionPublicKeyBytes, nodeLookup.EncryptionPublicKeyBytes)
	assert.Equal(nodeInfo.RegistrationNonce, nodeLookup.RegistrationNonce)
	assert.Equal(nodeInfo.CertificatePublicKeyPkix, nodeLookup.CertificatePublicKeyPkix)
	assert.Equal(nodeInfo.State.AsMap(), nodeLookup.State.AsMap())

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

	repo, err := NewRepository(rw, rw, kmsCache)
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
	databaseWrapper, err := kmsCache.GetWrapper(context.Background(), scope.Global.String(), kms.KeyPurposeDatabase)
	require.NoError(t, err)

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
		fileStorage, err := file.New(testCtx)
		require.NoError(t, err)
		nodeCreds, err := types.NewNodeCredentials(testCtx, fileStorage)
		require.NoError(t, err)

		nodePubKey, err := curve25519.X25519(nodeCreds.EncryptionPrivateKeyBytes, curve25519.Basepoint)
		require.NoError(t, err)
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

	tests := []struct {
		name            string
		writer          db.Writer
		databaseWrapper wrapping.Wrapper
		node            *types.NodeInformation
		wantErr         bool
		wantErrIs       errors.Code
		wantErrContains string
	}{
		{
			name:            "missing-writer",
			databaseWrapper: databaseWrapper,
			node:            testNodeInfoFn(),
			wantErr:         true,
			wantErrIs:       errors.InvalidParameter,
			wantErrContains: "missing writer",
		},
		{
			name:            "missing-wrapper",
			writer:          rw,
			node:            testNodeInfoFn(),
			wantErr:         true,
			wantErrIs:       errors.InvalidParameter,
			wantErrContains: "missing database wrapper",
		},
		{
			name:            "missing-node",
			writer:          rw,
			databaseWrapper: databaseWrapper,
			wantErr:         true,
			wantErrIs:       errors.InvalidParameter,
			wantErrContains: "missing NodeInformation",
		},
		{
			name:            "key-id-error",
			writer:          rw,
			databaseWrapper: &mockTestWrapper{err: errors.New(testCtx, errors.Internal, "testing", "key-id-error")},
			node:            testNodeInfoFn(),
			wantErr:         true,
			wantErrIs:       errors.Internal,
			wantErrContains: "key-id-error",
		},
		{
			name:   "encrypt-error",
			writer: rw,
			databaseWrapper: &mockTestWrapper{
				encryptError: true,
				err:          errors.New(testCtx, errors.Encrypt, "testing", "encrypt-error"),
			},
			node:            testNodeInfoFn(),
			wantErr:         true,
			wantErrIs:       errors.Encrypt,
			wantErrContains: "encrypt-error",
		},
		{
			name:            "create-error-no-db",
			writer:          &db.Db{},
			databaseWrapper: databaseWrapper,
			node:            testNodeInfoFn(),
			wantErr:         true,
			wantErrContains: "db.Create",
		},
		{
			name:            "create-error-validation",
			writer:          rw,
			databaseWrapper: databaseWrapper,
			node: func() *types.NodeInformation {
				ni := testNodeInfoFn()
				ni.State = nil
				return ni
			}(),
			wantErr:         true,
			wantErrContains: "missing WorkerId",
		},
		{
			name:            "success",
			writer:          rw,
			databaseWrapper: databaseWrapper,
			node:            testNodeInfoFn(),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			err := StoreNodeInformationTx(testCtx, tc.writer, tc.databaseWrapper, tc.node)
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
	panic("todo")
}

func (m *mockTestWrapper) Decrypt(ctx context.Context, ciphertext *wrapping.BlobInfo, options ...wrapping.Option) ([]byte, error) {
	if m.err != nil && m.decryptError {
		return nil, m.err
	}
	return []byte("decrypted"), nil
}
