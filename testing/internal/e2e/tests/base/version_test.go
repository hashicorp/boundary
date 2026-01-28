// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package base_test

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/boundary/version"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCliVersion validates the output from `boundary version`
func TestCliVersion(t *testing.T) {
	e2e.MaybeSkipTest(t)

	ctx := t.Context()
	output := e2e.RunCommand(ctx, "boundary", e2e.WithArgs("version", "-format", "json"))
	require.NoError(t, output.Err, string(output.Stderr))

	var versionResult version.Info
	err := json.Unmarshal(output.Stdout, &versionResult)
	require.NoError(t, err)

	parts := strings.Split(versionResult.Version, ".")
	assert.Equal(t, 3, len(parts), "Incorrect number of parts in version %q. EXPECTED: 3, ACTUAL: %d", versionResult.Version, len(parts))

	for _, v := range parts {
		_, err := strconv.Atoi(v)
		assert.NoError(t, err, "Invalid value in version %q. EXPECTED: Number, ACTUAL: %s", versionResult.Version, v)
	}
}
