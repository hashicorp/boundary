// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package test

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_IsTestRun(t *testing.T) {
	require.True(t, IsTestRun())
}
