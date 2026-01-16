// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package base

const (
	// FlagNameAddr is the flag used in the base command to read in the
	// address of the Boundary server.
	FlagNameAddr = "addr"
	// FlagnameCACert is the flag used in the base command to read in the CA
	// cert.
	FlagNameCACert = "ca-cert"
	// FlagnameCAPath is the flag used in the base command to read in the CA
	// cert path.
	FlagNameCAPath = "ca-path"
	// FlagNameClientCert is the flag used in the base command to read in the
	// client key
	FlagNameClientKey = "client-key"
	// FlagNameClientCert is the flag used in the base command to read in the
	// client cert
	FlagNameClientCert = "client-cert"
	// FlagNameTLSInsecure is the flag used in the base command to read in
	// the option to ignore TLS certificate verification.
	FlagNameTLSInsecure = "tls-insecure"
	// FlagTLSServerName is the flag used in the base command to read in
	// the TLS server name.
	FlagTLSServerName = "tls-server-name"
)

const (
	EnvBoundaryCLINoColor = `BOUNDARY_CLI_NO_COLOR`
	EnvBoundaryCLIFormat  = `BOUNDARY_CLI_FORMAT`
)
