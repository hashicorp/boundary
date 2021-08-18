package server

import (
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/config"
	"github.com/hashicorp/boundary/internal/servers/controller"
	"github.com/mitchellh/cli"
	"github.com/stretchr/testify/require"
)

// We try to pull these from TestController, but targets et al are
// computed off of a suffix instead of having constants. Just define
// for now here, this can be tweaked later if need be.
const defaultTestTargetId = "ttcp_1234567890"

const rootKmsConfig = `
kms "aead" {
	purpose = "root"
	aead_type = "aes-gcm"
	key = "%s"
	key_id = "global_root"
}`

type testServerCommandOpts struct {
	// Whether or not to create the dev database
	CreateDevDatabase bool

	// The controller key used in dev database creation
	ControllerKey string

	// Use the well-known dev mode auth method id (1234567890)
	UseDevAuthMethod bool

	// Use the well-known dev mode target method id (1234567890)
	UseDevTarget bool
}

func testServerCommand(t *testing.T, opts testServerCommandOpts) *Command {
	require := require.New(t)
	t.Helper()
	cmd := &Command{
		Server:     base.NewServer(base.NewCommand(cli.NewMockUi())),
		SighupCh:   base.MakeSighupCh(),
		startedCh:  make(chan struct{}),
		reloadedCh: make(chan struct{}, 5),
	}

	require.NoError(cmd.SetupLogging("trace", "", "", ""))
	require.NoError(cmd.SetupEventing(cmd.Logger, cmd.StderrLock, "test-server-command"))

	if opts.CreateDevDatabase {
		kmsHcl := fmt.Sprintf(rootKmsConfig, opts.ControllerKey)
		parsedKmsConfig, err := config.Parse(kmsHcl)
		require.NoError(err)
		require.NoError(cmd.SetupKMSes(cmd.UI, parsedKmsConfig))

		if opts.UseDevAuthMethod {
			cmd.Server.DevPasswordAuthMethodId = controller.DefaultTestPasswordAuthMethodId
			cmd.Server.DevLoginName = controller.DefaultTestLoginName
			cmd.Server.DevPassword = controller.DefaultTestPassword
		}

		if opts.UseDevTarget {
			cmd.Server.DevTargetId = defaultTestTargetId
		}

		err = cmd.CreateDevDatabase(cmd.Context, base.WithContainerImage("postgres"), base.WithSkipOidcAuthMethodCreation())
		if err != nil {
			if cmd.DevDatabaseCleanupFunc != nil {
				require.NoError(cmd.DevDatabaseCleanupFunc())
			}
			require.NoError(err)
		}
	}

	return cmd
}
