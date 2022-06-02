package servers

import (
	"context"
	"crypto/rand"
	"testing"

	"github.com/fatih/structs"
	"github.com/mitchellh/mapstructure"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/registration"
	"github.com/hashicorp/nodeenrollment/rotation"
	"github.com/hashicorp/nodeenrollment/storage/file"
	"github.com/hashicorp/nodeenrollment/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/curve25519"
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
	noCertAuth := &types.RootCertificates{Id: ca_id}
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
	certAuthority := &types.RootCertificates{Id: ca_id}
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

	cAuth2 := &types.RootCertificates{Id: ca_id}
	err = workerAuthRepo.Load(ctx, cAuth2)
	require.NoError(err)
	var result2 rootCertificatesVersion
	err = mapstructure.Decode(cAuth2.State.AsMap(), &result2)
	require.NoError(err)
	assert.Equal(uint32(2), result2.Version)

	// Store CA with old version, expect error
	badVersion := &rootCertificatesVersion{Version: uint32(1)}
	badStateOpt := structs.Map(badVersion)
	badState, err := structpb.NewStruct(badStateOpt)
	require.NoError(err)
	newRoots2 := &types.RootCertificates{
		Id:      ca_id,
		Next:    roots.Next,
		Current: roots.Current,
	}
	newRoots2.State = badState
	err = workerAuthRepo.Store(ctx, newRoots2)
	require.Error(err)

	// Remove CA, expect updated version
	cAuthRemove := &types.RootCertificates{Id: ca_id}
	removeVersion := &rootCertificatesVersion{Version: uint32(2)}
	removeOpt := structs.Map(removeVersion)
	removeState, err := structpb.NewStruct(removeOpt)
	require.NoError(err)
	cAuthRemove.State = removeState
	err = workerAuthRepo.Remove(ctx, cAuthRemove)
	require.NoError(err)
}

// Test WorkerAuth storage
func TestStoreWorkerAuth(t *testing.T) {
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

	worker := TestWorker(t, conn, wrapper)

	rw := db.New(conn)
	rootStorage, err := NewRepositoryStorage(ctx, rw, rw, kmsCache)
	require.NoError(err)

	_, err = rotation.RotateRootCertificates(ctx, rootStorage)
	require.NoError(err)

	// Create struct to pass in with workerId that will be passed along to storage
	state, err := AttachWorkerIdToState(ctx, worker.PublicId)
	require.NoError(err)

	// This happens on the worker
	fileStorage, err := file.NewFileStorage(ctx)
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
	require.NoError(registration.AuthorizeNode(ctx, storage, fetchReq, nodeenrollment.WithState(state)))

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

	// Remove node
	err = storage.Remove(ctx, nodeLookup)
	require.NoError(err)
	err = storage.Load(ctx, nodeLookup)
	require.Error(err)
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
