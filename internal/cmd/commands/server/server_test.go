package server

import (
	"context"
	"sync"
	"testing"

	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/db/schema"
	"github.com/hashicorp/boundary/internal/docker"
	"github.com/mitchellh/cli"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
		c.ensureManagerConnection()
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
		c.ensureManagerConnection()
	}()

	close(c.ShutdownCh)
	wg.Wait()

	assert.Zero(t, ui.OutputWriter.String())
	assert.Zero(t, ui.ErrorWriter.String())
}