// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1


package vault

import "testing"

var (
	newVaultServer func(t testing.TB, opt ...TestOption) *TestVaultServer                  = skipNewServer
	mountDatabase  func(t testing.TB, v *TestVaultServer, opt ...TestOption) *TestDatabase = skipMountDatabase
)

func skipNewServer(t testing.TB, opt ...TestOption) *TestVaultServer {
	t.Skip("docker not available")
	return nil
}

func skipMountDatabase(t testing.TB, v *TestVaultServer, opt ...TestOption) *TestDatabase {
	t.Skip("docker not available")
	return nil
}
