package server

import (
	"context"
	"database/sql"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/db/schema"
	"github.com/hashicorp/boundary/internal/docker"
	"github.com/mitchellh/cli"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConnectSchemaManager(t *testing.T) {
	dialect := "postgres"
	ctx := context.Background()

	cases := []struct {
		name string
		prep func(*sql.DB)
		err  bool
	}{
		{
			name: "valid",
			prep: func(d *sql.DB) {
				m, err := schema.NewManager(ctx, dialect, d)
				require.NoError(t, err)
				require.NoError(t, m.RollForward(ctx))
			},
		},
		{
			name: "not initialized",
			err:  true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ui := cli.NewMockUi()
			ch := make(chan struct{})
			c := &Command{
				Server:    base.NewServer(base.NewCommand(ui)),
				SighupCh:  ch,
				SigUSR2Ch: ch,
			}
			defer c.CancelFn()

			end, u, _, err := docker.StartDbInDocker(dialect)
			require.NoError(t, err)
			defer end()

			c.DatabaseUrl = u
			require.NoError(t, c.ConnectToDatabase(dialect))

			if tc.prep != nil {
				tc.prep(c.Database.DB())
			}

			err = c.connectSchemaManager(dialect)
			if tc.err {
				assert.Error(t, err)
				assert.Nil(t, c.SchemaManager)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, c.SchemaManager)
			}
		})
	}
}

func TestEnsureManagerConnection_DBDisconnect(t *testing.T) {
	ui := cli.NewMockUi()
	ch := make(chan struct{})
	c := &Command{
		Server:    base.NewServer(base.NewCommand(ui)),
		SighupCh:  ch,
		SigUSR2Ch: ch,
	}

	ctx := context.Background()
	dialect := "postgres"
	end, u, _, err := docker.StartDbInDocker(dialect)
	require.NoError(t, err)
	defer end()

	c.DatabaseUrl = u
	require.NoError(t, c.ConnectToDatabase(dialect))

	m, err := schema.NewManager(ctx, dialect, c.Database.DB())
	require.NoError(t, err)
	require.NoError(t, m.RollForward(ctx))

	require.NoError(t, c.connectSchemaManager(dialect))

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		c.ensureManagerConnection(time.Millisecond)
	}()

	end()
	wg.Wait()

	assert.Zero(t, ui.OutputWriter.String())
	assert.Equal(t, "The Schema Manager lost connection with the DB and cannot ensure it's integrity.\n", ui.ErrorWriter.String())
}

func TestEnsureManagerConnection_Shutdown(t *testing.T) {
	ui := cli.NewMockUi()
	ch := make(chan struct{})
	c := &Command{
		Server:    base.NewServer(base.NewCommand(ui)),
		SighupCh:  ch,
		SigUSR2Ch: ch,
	}

	ctx := context.Background()
	dialect := "postgres"
	end, u, _, err := docker.StartDbInDocker(dialect)
	require.NoError(t, err)
	defer end()

	c.DatabaseUrl = u
	require.NoError(t, c.ConnectToDatabase(dialect))

	m, err := schema.NewManager(ctx, dialect, c.Database.DB())
	require.NoError(t, err)
	require.NoError(t, m.RollForward(ctx))

	require.NoError(t, c.connectSchemaManager(dialect))

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		c.ensureManagerConnection(time.Millisecond)
	}()

	close(c.ShutdownCh)
	wg.Wait()

	assert.Zero(t, ui.OutputWriter.String())
	assert.Zero(t, ui.ErrorWriter.String())
}
