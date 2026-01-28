// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package dev

import (
	"bufio"
	"os"
	"testing"

	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/mitchellh/cli"
	"github.com/stretchr/testify/assert"
)

func TestCommand_Flags(t *testing.T) {
	t.Parallel()
	assert := assert.New(t)

	serverCmdUi := &base.BoundaryUI{
		Ui: &cli.ColoredUi{
			ErrorColor: cli.UiColorRed,
			WarnColor:  cli.UiColorYellow,
			Ui: &cli.BasicUi{
				Reader: bufio.NewReader(os.Stdin),
				Writer: os.Stdout,
			},
		},
		Format: "table",
	}
	base.NewServer(base.NewCommand(serverCmdUi))

	cmd := &Command{Server: base.NewServer(base.NewCommand(serverCmdUi))}
	got := cmd.Flags()
	completions := got.Completions()

	assert.Contains(completions, "-log-level")
	assert.Contains(completions, "-log-format")
	assert.Contains(completions, "-id-suffix")
	assert.Contains(completions, "-password")
	assert.Contains(completions, "-login-name")
	assert.Contains(completions, "-unprivileged-password")
	assert.Contains(completions, "-unprivileged-login-name")
	assert.Contains(completions, "-api-listen-address")
	assert.Contains(completions, "-host-address")
	assert.Contains(completions, "-target-default-port")
	assert.Contains(completions, "-target-session-connection-limit")
	assert.Contains(completions, "-target-session-max-seconds")
	assert.Contains(completions, "-cluster-listen-address")
	assert.Contains(completions, "-controller-public-cluster-address")
	assert.Contains(completions, "-ops-listen-address")
	assert.Contains(completions, "-controller-only")
	assert.Contains(completions, "-proxy-listen-address")
	assert.Contains(completions, "-worker-public-address")
	assert.Contains(completions, "-worker-auth-key")
	assert.Contains(completions, "-disable-database-destruction")
	assert.Contains(completions, "-combine-logs")
	assert.Contains(completions, "-ui-passthrough-dir")
	assert.Contains(completions, "-recovery-key")
	assert.Contains(completions, "-database-url")
	assert.Contains(completions, "-container-image")
	assert.Contains(completions, "-event-format")
	assert.Contains(completions, "-observation-events")
	assert.Contains(completions, "-telemetry-events")
	assert.Contains(completions, "-audit-events")
	assert.Contains(completions, "-system-events")
	assert.Contains(completions, "-audit-events")
	assert.Contains(completions, "-event-allow-filter")
	assert.Contains(completions, "-event-deny-filter")
	assert.Contains(completions, "-plugin-execution-dir")
	assert.Contains(completions, "-worker-auth-method")
	assert.Contains(completions, "-worker-auth-storage-dir")
	assert.Contains(completions, "-worker-recording-storage-dir")
	assert.Contains(completions, "-worker-recording-storage-minimum-available-capacity")
	assert.Contains(completions, "-worker-auth-storage-skip-cleanup")

	// keep adding assertions for other flags which should be set as a result of cmd.Flags()
}
