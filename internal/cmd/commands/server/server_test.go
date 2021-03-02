package server

import (
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/config"
	"github.com/mitchellh/cli"
	"github.com/stretchr/testify/require"
)

const rootKmsConfig = `
kms "aead" {
	purpose = "root"
	aead_type = "aes-gcm"
	key = "%s"
	key_id = "global_root"
}`

func testServerCommand(t *testing.T, controllerKey string) *Command {
	require := require.New(t)
	t.Helper()
	cmd := &Command{
		Server:      base.NewServer(base.NewCommand(cli.NewMockUi())),
		SighupCh:    base.MakeSighupCh(),
		startedCh:   make(chan struct{}),
		reloadedCh:  make(chan struct{}, 5),
		skipMetrics: true,
	}

	require.NoError(cmd.SetupLogging("trace", "", "", ""))

	kmsHcl := fmt.Sprintf(rootKmsConfig, controllerKey)
	parsedKmsConfig, err := config.Parse(kmsHcl)
	require.NoError(err)
	require.NoError(cmd.SetupKMSes(cmd.UI, parsedKmsConfig))

	err = cmd.CreateDevDatabase(cmd.Context, "postgres")
	if err != nil {
		if cmd.DevDatabaseCleanupFunc != nil {
			require.NoError(cmd.DevDatabaseCleanupFunc())
		}
		require.NoError(err)
	}

	return cmd
}
