// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package boundary

import (
	"context"
	"encoding/json"
	"testing"

	gvers "github.com/hashicorp/go-version"
	"github.com/stretchr/testify/require"

	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/boundary/version"
)

// IsVersionAtLeast checks if the Boundary version running in the specified container is at least the given minimum version.
func IsVersionAtLeast(t testing.TB, ctx context.Context, containerName string, minVersion string) {
	output := e2e.RunCommand(
		ctx,
		"docker",
		e2e.WithArgs(
			"exec", containerName,
			"boundary", "version",
			"-format", "json",
		),
	)
	require.NoError(t, output.Err, "failed to get version from container %q: %s", containerName, string(output.Stderr))

	var versionResult version.Info
	err := json.Unmarshal(output.Stdout, &versionResult)
	require.NoError(t, err)

	minSemVersion, err := gvers.NewSemver(minVersion)
	require.NoError(t, err)

	containerVersion := versionResult.Semver()
	require.NotNil(t, containerVersion, "failed to parse version %q from container %q", versionResult.VersionNumber(), containerName)

	if !containerVersion.GreaterThanOrEqual(minSemVersion) {
		t.Skipf(
			"Skipping test because container %q is running %q, but this test requires >= %q",
			containerName,
			versionResult.VersionNumber(),
			minVersion,
		)
	}
}
