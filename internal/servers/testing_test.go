package servers

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTestWorker(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	tWorker := TestWorker(t, conn, wrapper)
	assert.NotNil(t, tWorker)
	assert.True(t, strings.HasPrefix(tWorker.GetPublicId(), WorkerPrefix))

	lkpWorker := NewWorker(scope.Global.String())
	lkpWorker.PublicId = tWorker.GetPublicId()
	rw := db.New(conn)
	require.NoError(t, rw.LookupById(context.Background(), lkpWorker))
	assert.NotNil(t, lkpWorker)
}
