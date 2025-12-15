// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"crypto/rand"
	mathRand "math/rand"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/server/store"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/boundary/version"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/registration"
	"github.com/hashicorp/nodeenrollment/rotation"
	"github.com/hashicorp/nodeenrollment/storage/file"
	"github.com/hashicorp/nodeenrollment/types"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const defaultLength = 20

// Generate random bytes for byte fields
func populateBytes(length int) []byte {
	fieldBytes := make([]byte, length)
	if _, err := rand.Read(fieldBytes); err != nil {
		panic(err)
	}
	return fieldBytes
}

func TestKmsKey(ctx context.Context, t *testing.T, conn *db.DB, wrapper wrapping.Wrapper) (string, wrapping.Wrapper) {
	t.Helper()
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	kmsCache := kms.TestKms(t, conn, wrapper)
	databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)
	testKey, err := databaseWrapper.KeyId(ctx)
	require.NoError(t, err)

	return testKey, databaseWrapper
}

func TestRootCertificate(ctx context.Context, t *testing.T, conn *db.DB, kmsKey string) *RootCertificate {
	t.Helper()
	rw := db.New(conn)

	beforeTimestamp := &timestamp.Timestamp{Timestamp: timestamppb.New(time.Now().Add(-1 * time.Hour))}
	afterTimestamp := &timestamp.Timestamp{Timestamp: timestamppb.New(time.Now().Add(1 * time.Hour))}

	rootCertKeys := RootCertificateKeys{
		publicKey:  populateBytes(defaultLength),
		privateKey: populateBytes(defaultLength),
	}

	cert, err := newRootCertificate(ctx, mathRand.Uint64(), populateBytes(defaultLength), beforeTimestamp, afterTimestamp,
		rootCertKeys, kmsKey, CurrentState)
	require.NoError(t, err)
	err = rw.Create(ctx, cert)
	require.NoError(t, err)
	return cert
}

func TestWorkerAuth(t *testing.T, conn *db.DB, worker *Worker, kmsWrapper wrapping.Wrapper) *WorkerAuth {
	t.Helper()
	ctx := context.Background()
	rw := db.New(conn)
	wSignPubKey := populateBytes(defaultLength)
	wEncPubKey := populateBytes(defaultLength)
	workerKeys := WorkerKeys{workerSigningPubKey: wSignPubKey, workerEncryptionPubKey: wEncPubKey}
	controllerKey := populateBytes(defaultLength)
	nonce := populateBytes(defaultLength)
	opt := []Option{
		WithWorkerKeys(workerKeys),
		WithControllerEncryptionPrivateKey(controllerKey),
		WithNonce(nonce),
	}

	workerAuth, err := newWorkerAuth(ctx, "worker-key-identifier", worker.PublicId, opt...)
	require.NoError(t, err)
	require.NoError(t, workerAuth.encrypt(ctx, kmsWrapper))
	require.NoError(t, rw.Create(ctx, workerAuth))

	return workerAuth
}

// TestKmsWorker inserts a worker into the db to satisfy foreign key constraints.
// The worker provided fields are auto generated. if WithName is not present a
// random name will be generated and assigned to the worker.
func TestKmsWorker(t *testing.T, conn *db.DB, wrapper wrapping.Wrapper, opt ...Option) *Worker {
	t.Helper()
	ctx := context.Background()
	rw := db.New(conn)
	kms := kms.TestKms(t, conn, wrapper)
	serversRepo, err := NewRepository(ctx, rw, rw, kms)
	require.NoError(t, err)
	opts := GetOpts(opt...)

	if opts.withName == "" {
		namePart, err := newWorkerId(ctx)
		require.NoError(t, err)
		name := "test-worker-" + strings.ToLower(namePart)
		opt = append(opt, WithName(name))
	}
	if opts.withAddress == "" {
		address := "127.0.0.1"
		opt = append(opt, WithAddress(address))
	}
	if opts.withReleaseVersion == "" {
		// Only set the release version if it isn't already set
		versionInfo := version.Get()
		relVer := versionInfo.FullVersionNumber(false)
		opt = append(opt, WithReleaseVersion(relVer))
	}

	wrk := NewWorker(scope.Global.String(), opt...)
	wrk, err = TestUpsertAndReturnWorker(ctx, t, wrk, serversRepo)
	require.NoError(t, err)
	require.NoError(t, err)
	require.NotNil(t, wrk)
	require.Equal(t, "kms", wrk.Type)

	if len(opts.withWorkerTags) > 0 {
		var tags []*store.ConfigTag
		for _, t := range opts.withWorkerTags {
			tags = append(tags, &store.ConfigTag{
				WorkerId: wrk.GetPublicId(),
				Key:      t.Key,
				Value:    t.Value,
			})
		}
		require.NoError(t, rw.CreateItems(ctx, tags))
	}

	wrk, err = serversRepo.LookupWorker(ctx, wrk.GetPublicId())
	require.NoError(t, err)
	return wrk
}

// TestPkiWorker inserts a worker into the db to satisfy foreign key constraints.
// The worker provided fields are auto generated. WithName and WithDescription,
// are applied to the resource name, description if present.  WithTestPkiWorkerAuthorizedKeyId
// can be used to make the PkiWorker authorized in which case the string pointer
// passed to WithTestPkiWorkerAuthorizedKeyId is set to the key id.
func TestPkiWorker(t *testing.T, conn *db.DB, wrapper wrapping.Wrapper, opt ...Option) *Worker {
	t.Helper()
	ctx := context.Background()
	rw := db.New(conn)
	kmsCache := kms.TestKms(t, conn, wrapper)
	serversRepo, err := NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(t, err)
	opts := GetOpts(opt...)

	require.NoError(t, err)
	wrk := NewWorker(scope.Global.String(),
		opt...)
	wrk, err = serversRepo.CreateWorker(ctx, wrk, opt...)
	require.NoError(t, err)
	require.NotNil(t, wrk)

	if len(opts.withWorkerTags) > 0 {
		switch opts.withTestUseInputTagsAsApiTags {
		case true:
			var tags []*store.ApiTag
			for _, t := range opts.withWorkerTags {
				tags = append(tags, &store.ApiTag{
					WorkerId: wrk.GetPublicId(),
					Key:      t.Key,
					Value:    t.Value,
				})
			}
			require.NoError(t, rw.CreateItems(ctx, tags))
		default:
			var tags []*store.ConfigTag
			for _, t := range opts.withWorkerTags {
				tags = append(tags, &store.ConfigTag{
					WorkerId: wrk.GetPublicId(),
					Key:      t.Key,
					Value:    t.Value,
				})
			}
			require.NoError(t, rw.CreateItems(ctx, tags))
		}
	}
	if opts.withTestPkiWorkerAuthorized {
		err = kmsCache.CreateKeys(context.Background(), scope.Global.String(), kms.WithRandomReader(rand.Reader))
		// We always try to create root global scope keys, but if it already exists, just continue...
		require.True(t, err == nil || errors.IsUniqueError(err), err)
		rootStorage, err := NewRepositoryStorage(ctx, rw, rw, kmsCache)
		require.NoError(t, err)
		_, err = rotation.RotateRootCertificates(ctx, rootStorage)
		require.NoError(t, err)
		// Create struct to pass in with workerId that will be passed along to storage
		state, err := AttachWorkerIdToState(ctx, wrk.PublicId)
		require.NoError(t, err)

		// This happens on the worker
		fileStorage, err := file.New(ctx)
		require.NoError(t, err)
		nodeCreds, err := types.NewNodeCredentials(ctx, fileStorage)
		require.NoError(t, err)
		// Create request using worker id
		fetchReq, err := nodeCreds.CreateFetchNodeCredentialsRequest(ctx)
		require.NoError(t, err)
		registeredNode, err := registration.AuthorizeNode(ctx, rootStorage, fetchReq, nodeenrollment.WithState(state))
		require.NoError(t, err)

		if opts.withTestPkiWorkerKeyId != nil {
			*opts.withTestPkiWorkerKeyId = registeredNode.Id
		}
	}
	wrk, err = serversRepo.LookupWorker(ctx, wrk.GetPublicId())
	require.NoError(t, err)
	return wrk
}

// TestLookupWorkerByName looks up a worker by name
func TestLookupWorkerByName(ctx context.Context, t *testing.T, name string, serversRepo *Repository) (*Worker, error) {
	workers, err := serversRepo.ListWorkers(ctx, []string{"global"})
	require.NoError(t, err)
	for _, w := range workers {
		if w.GetName() == name {
			return w, nil
		}
	}
	return nil, nil
}

// TestUpsertAndReturnWorker upserts and returns a worker
func TestUpsertAndReturnWorker(ctx context.Context, t *testing.T, w *Worker, serversRepo *Repository, opt ...Option) (*Worker, error) {
	workerId, err := serversRepo.UpsertWorkerStatus(ctx, w, opt...)
	require.NoError(t, err)
	require.NotEmpty(t, workerId)
	return serversRepo.LookupWorker(ctx, workerId)
}

// TestUseCommunityFilterWorkersFn is used to ensure that CE tests run from the
// ENT repo use the CE worker filtering logic. WARNING: Do NOT run tests in
// parallel when using this.
func TestUseCommunityFilterWorkersFn(t *testing.T) {
	oldFn := FilterWorkersFn
	FilterWorkersFn = filterWorkers

	t.Cleanup(func() {
		FilterWorkersFn = oldFn
	})
}
