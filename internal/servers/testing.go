package servers

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/stretchr/testify/require"
)

// TestWorker inserts a worker into the db to satisfy foreign key constraints.
func TestWorker(t *testing.T, conn *db.DB, wrapper wrapping.Wrapper) *Worker {
	t.Helper()
	rw := db.New(conn)
	kms := kms.TestKms(t, conn, wrapper)
	serversRepo, err := NewRepository(rw, rw, kms)
	require.NoError(t, err)

	id, err := newWorkerId(context.Background())
	require.NoError(t, err)
	name := "test-worker-" + id

	worker := NewWorker(scope.Global.String(),
		WithPublicId(id),
		WithName(name),
		WithAddress("127.0.0.1"))
	_, _, err = serversRepo.UpsertWorker(context.Background(), worker)
	require.NoError(t, err)
	return worker
}
