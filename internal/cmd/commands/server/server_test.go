// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/config"
	"github.com/hashicorp/boundary/internal/daemon/controller"
	"github.com/mitchellh/cli"
	"github.com/stretchr/testify/require"
)

// We try to pull these from TestController, but targets et al are
// computed off of a suffix instead of having constants. Just define
// for now here, this can be tweaked later if need be.
const (
	defaultTestTargetId          = "ttcp_1234567890"
	defaultSecondaryTestTargetId = "ttcp_0987654321"

	rootKmsConfig = `
kms "aead" {
	purpose = "root"
	aead_type = "aes-gcm"
	key = "%s"
	key_id = "global_root"
}`
)

type testServerCommandOpts struct {
	// Whether or not to create the dev database
	CreateDevDatabase bool

	// The controller key used in dev database creation
	ControllerKey string

	// Use the well-known dev mode auth method id (1234567890)
	UseDevAuthMethod bool

	// Use the well-known dev mode target method ids (1234567890 and 0987654321)
	UseDevTargets bool

	// Whether or not to enable metric collection. If enable metrics will use
	// prometheus' default registerer.
	EnableMetrics bool
}

func testServerCommand(t *testing.T, opts testServerCommandOpts) *Command {
	require := require.New(t)
	t.Helper()
	cmd := &Command{
		Server:     base.NewServer(base.NewServerCommand(cli.NewMockUi())),
		SighupCh:   base.MakeSighupCh(),
		startedCh:  make(chan struct{}),
		reloadedCh: make(chan struct{}, 5),
	}

	require.NoError(cmd.SetupLogging("trace", "", "", ""))
	require.NoError(cmd.SetupEventing(cmd.Context, cmd.Logger, cmd.StderrLock, "test-server-command"))

	if !opts.EnableMetrics {
		cmd.PrometheusRegisterer = nil
	}

	if opts.CreateDevDatabase {
		kmsHcl := fmt.Sprintf(rootKmsConfig, opts.ControllerKey)
		parsedKmsConfig, err := config.Parse(kmsHcl)
		require.NoError(err)
		require.NoError(cmd.SetupKMSes(cmd.Context, cmd.UI, parsedKmsConfig))

		if opts.UseDevAuthMethod {
			cmd.Server.DevPasswordAuthMethodId = controller.DefaultTestPasswordAuthMethodId
			cmd.Server.DevLoginName = controller.DefaultTestLoginName
			cmd.Server.DevPassword = controller.DefaultTestPassword
		}

		if opts.UseDevTargets {
			cmd.Server.DevTargetId = defaultTestTargetId
			cmd.Server.DevSecondaryTargetId = defaultSecondaryTestTargetId
		}

		err = cmd.CreateDevDatabase(cmd.Context, base.WithDatabaseTemplate("boundary_template"), base.WithSkipOidcAuthMethodCreation(), base.WithSkipLdapAuthMethodCreation())
		if err != nil {
			if cmd.DevDatabaseCleanupFunc != nil {
				require.NoError(cmd.DevDatabaseCleanupFunc())
			}
			require.NoError(err)
		}
	}

	return cmd
}
