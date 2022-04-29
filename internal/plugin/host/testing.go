package host

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/stretchr/testify/require"
)

func TestPlugin(t testing.TB, conn *db.DB, name string) *Plugin {
	t.Helper()
	p := NewPlugin(WithName(name))
	id, err := newPluginId()
	require.NoError(t, err)
	p.PublicId = id

	w := db.New(conn)
	require.NoError(t, w.Create(context.Background(), p))
	return p
}
