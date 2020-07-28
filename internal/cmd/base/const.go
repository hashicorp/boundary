package base

const (
	// FlagNameAddr is the flag used in the base command to read in the
	// address of the Watchtower server.
	FlagNameAddr = "addr"
	// FlagNameScope is the flag used in the base command to read in the scope
	// in which to make a request.
	FlagNameScope = "scope"
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
	EnvWatchtowerCLINoColor = `WATCHTOWER_CLI_NO_COLOR`
	EnvWatchtowerCLIFormat  = `WATCHTOWER_CLI_FORMAT`
)
