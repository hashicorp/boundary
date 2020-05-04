package base

const (
	// flagNameAddress is the flag used in the base command to read in the
	// address of the Watchtower server.
	FlagNameAddress = "address"
	// flagnameCACert is the flag used in the base command to read in the CA
	// cert.
	FlagNameCACert = "ca-cert"
	// flagnameCAPath is the flag used in the base command to read in the CA
	// cert path.
	FlagNameCAPath = "ca-path"
	//flagNameClientCert is the flag used in the base command to read in the
	//client key
	FlagNameClientKey = "client-key"
	//flagNameClientCert is the flag used in the base command to read in the
	//client cert
	FlagNameClientCert = "client-cert"
	// flagNameTLSInsecure is the flag used in the base command to read in
	// the option to ignore TLS certificate verification.
	FlagNameTLSInsecure = "tls-insecure"
	// flagTLSServerName is the flag used in the base command to read in
	// the TLS server name.
	FlagTLSServerName = "tls-server-name"
)

const EnvWatchtowerCLINoColor = `WATCHTOWER_CLI_NO_COLOR`
const EnvWatchtowerCLIFormat = `WATCHTOWER_CLI_FORMAT`

