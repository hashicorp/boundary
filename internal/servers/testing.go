package servers

import (
	"context"
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/types/scope"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
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

func TestRootCertificate(ctx context.Context, t *testing.T, conn *db.DB, kmsKey string) *RootCertificate {
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
	return cert
}

func TestWorkerAuth(ctx context.Context, t *testing.T, conn *db.DB, worker *Worker, kmsKey string) *WorkerAuth {
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

	return workerAuth
}

// TestWorker inserts a worker into the db to satisfy foreign key constraints.
// The worker provided fields are auto generated. WithName, WithDescription,
// and WithAddress are applied to the resource name, description and address if
// present.
func TestWorker(t *testing.T, conn *db.DB, wrapper wrapping.Wrapper, opt ...Option) *Worker {
	t.Helper()
	rw := db.New(conn)
	kms := kms.TestKms(t, conn, wrapper)
	serversRepo, err := NewRepository(rw, rw, kms)
	require.NoError(t, err)
	ctx := context.Background()

	namePart, err := newWorkerId(context.Background())
	require.NoError(t, err)
	name := "test-worker-" + strings.ToLower(namePart)
	wrk := NewWorkerForStatus(scope.Global.String(),
		WithName(name),
		WithAddress("127.0.0.1"))
	wrk, err = serversRepo.UpsertWorkerStatus(context.Background(), wrk)
	require.NoError(t, err)
	require.NotNil(t, wrk)
	opts := getOpts(opt...)

	var mask []string
	if opts.withName != "" {
		wrk.Name = opts.withName
		mask = append(mask, "name")
	}
	if opts.withDescription != "" {
		wrk.Description = opts.withDescription
		mask = append(mask, "description")
	}
	if opts.withAddress != "" {
		wrk.Address = opts.withAddress
		mask = append(mask, "address")
	}
	if len(mask) > 0 {
		var n int
		wrk, n, err = serversRepo.UpdateWorker(ctx, wrk, wrk.Version, mask)
		require.NoError(t, err)
		require.Equal(t, 1, n)
		require.NotNil(t, wrk)
	}

	return wrk
}
