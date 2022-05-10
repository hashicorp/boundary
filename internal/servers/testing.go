package servers

import (
	"context"
	"math/rand"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/servers/store"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-uuid"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const defaultLength = 20

// Generate random bytes for byte fields
func populateBytes(length int) []byte {
	fieldBytes := make([]byte, length)
	rand.Read(fieldBytes)
	return fieldBytes
}

func TestKkmsKey(ctx context.Context, t *testing.T, conn *db.DB, wrapper wrapping.Wrapper) string {
	t.Helper()
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	kmsCache := kms.TestKms(t, conn, wrapper)
	databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)
	testKey, err := databaseWrapper.KeyId(ctx)
	require.NoError(t, err)

	return testKey
}

func TestRootCertificate(ctx context.Context, t *testing.T, conn *db.DB, kmsKey string) *store.RootCertificate {
	t.Helper()
	rw := db.New(conn)

	beforeTimestamp := &timestamp.Timestamp{Timestamp: timestamppb.New(time.Now().Add(-1 * time.Hour))}
	afterTimestamp := &timestamp.Timestamp{Timestamp: timestamppb.New(time.Now().Add(1 * time.Hour))}

	rootCertKeys := RootCertificateKeys{
		publicKey:  populateBytes(defaultLength),
		privateKey: populateBytes(defaultLength),
	}

	cert, err := newRootCertificate(ctx, rand.Uint64(), populateBytes(defaultLength), beforeTimestamp, afterTimestamp,
		rootCertKeys, kmsKey, CurrentState)
	err = rw.Create(ctx, cert)
	require.NoError(t, err)
	return cert.RootCertificate
}

func TestWorkerAuth(ctx context.Context, t *testing.T, conn *db.DB, worker *store.Worker, kmsKey string) *store.WorkerAuth {
	t.Helper()
	rw := db.New(conn)
	wSignPubKey := populateBytes(defaultLength)
	wEncPubKey := populateBytes(defaultLength)
	workerKeys := WorkerKeys{workerSigningPubKey: wSignPubKey, workerEncryptionPubKey: wEncPubKey}
	controllerKey := populateBytes(defaultLength)
	nonce := populateBytes(defaultLength)
	opt := []Option{
		WithKeyId(kmsKey),
		WithWorkerKeys(workerKeys),
		WithControllerEncryptionPrivateKey(controllerKey),
		WithNonce(nonce),
	}

	workerAuth, err := newWorkerAuth(ctx, "worker-key-identifier", worker.PublicId, opt...)
	require.NoError(t, err)
	err = rw.Create(ctx, workerAuth)
	require.NoError(t, err)

	return workerAuth.WorkerAuth
}

func TestWorker(t *testing.T, conn *db.DB, wrapper wrapping.Wrapper) *store.Worker {
	t.Helper()
	rw := db.New(conn)
	kms := kms.TestKms(t, conn, wrapper)
	serversRepo, err := NewRepository(rw, rw, kms)
	require.NoError(t, err)

	id, err := uuid.GenerateUUID()
	require.NoError(t, err)
	id = "test-session-worker-" + id

	name := "test-worker-" + id
	worker := &store.Worker{
		PublicId: id,
		Name:     name,
		Address:  "127.0.0.1",
	}
	_, _, err = serversRepo.UpsertWorker(context.Background(), worker)
	require.NoError(t, err)
	return worker
}
