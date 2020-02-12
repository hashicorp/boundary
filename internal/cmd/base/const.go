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
const EnvWatchtowerAddress = "WATCHTOWER_ADDR"
const EnvWatchtowerCACert = "WATCHTOWER_CACERT"
const EnvWatchtowerCAPath = "WATCHTOWER_CAPATH"
const EnvWatchtowerClientCert = "WATCHTOWER_CLIENT_CERT"
const EnvWatchtowerClientKey = "WATCHTOWER_CLIENT_KEY"
const EnvWatchtowerClientTimeout = "WATCHTOWER_CLIENT_TIMEOUT"
const EnvWatchtowerTLSInsecure = "WATCHTOWER_TLS_INSECURE"
const EnvWatchtowerTLSServerName = "WATCHTOWER_TLS_SERVER_NAME"
const EnvWatchtowerMaxRetries = "WATCHTOWER_MAX_RETRIES"
const EnvWatchtowerToken = "WATCHTOWER_TOKEN"
const EnvRateLimit = "WATCHTOWER_RATE_LIMIT"
