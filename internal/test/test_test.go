// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package test

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_IsTestRun(t *testing.T) {
	require.True(t, IsTestRun())
}
