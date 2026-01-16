// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package vault

import "testing"

var (
	newVaultServer  func(t testing.TB, opt ...TestOption) *TestVaultServer                    = skipNewServer
	mountLdapServer func(t testing.TB, v *TestVaultServer, opt ...TestOption) *TestLdapServer = skipMountLdapServer
	mountDatabase   func(t testing.TB, v *TestVaultServer, opt ...TestOption) *TestDatabase   = skipMountDatabase
)

func skipNewServer(t testing.TB, opt ...TestOption) *TestVaultServer {
	t.Skip("docker not available")
	return nil
}

func skipMountDatabase(t testing.TB, v *TestVaultServer, opt ...TestOption) *TestDatabase {
	t.Skip("docker not available")
	return nil
}

func skipMountLdapServer(t testing.TB, v *TestVaultServer, opt ...TestOption) *TestLdapServer {
	t.Skip("docker not available")
	return nil
}
