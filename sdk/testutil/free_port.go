// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: MPL-2.0

package testutil

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestFreePort just returns an available free localhost port
func TestFreePort(t testing.TB) int {
	t.Helper()
	require := require.New(t)
	addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
	require.NoError(err)

	l, err := net.ListenTCP("tcp", addr)
	require.NoError(err)
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}
