package vault

import "testing"

var (
	newVaultServer func(t *testing.T, opt ...TestOption) *TestVaultServer    = skipNewServer
	mountDatabase  func(t *testing.T, v *TestVaultServer, opt ...TestOption) = skipMountDatabase
)

func skipNewServer(t *testing.T, opt ...TestOption) *TestVaultServer {
	t.Skip("docker not available")
	return nil
}

func skipMountDatabase(t *testing.T, v *TestVaultServer, opt ...TestOption) {
	t.Skip("docker not available")
}
