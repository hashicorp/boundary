package globals

import "time"

const (
	TcpProxyV1     = "boundary-tcp-proxy-v1"
	ServiceTokenV1 = "s1"
)

type (
	ContextMaxRequestSizeType      struct{}
	ContextOriginalRequestPathType struct{}
)

var (
	// DefaultMaxRequestDuration is the amount of time we'll wait for a request
	DefaultMaxRequestDuration = 90 * time.Second

	// DefaultMaxRequestSize is the maximum size of a request we allow by default
	DefaultMaxRequestSize = int64(1024 * 1024)

	// ContextMaxRequestSizeTypeKey is a value to keep linters from complaining
	// about clashing string identifiers
	ContextMaxRequestSizeTypeKey ContextMaxRequestSizeType

	// ContextOriginalRequestPathTypeKey is a value to keep linters from complaining
	// about clashing string identifiers
	ContextOriginalRequestPathTypeKey ContextOriginalRequestPathType

	// RecoveryTokenValidityPeriod is exported so we can modify it in tests if
	// we want
	RecoveryTokenValidityPeriod = 5 * time.Minute

	// WorkerAuthNonceValidityPeriod is exported so we can modify it in tests if
	// we want
	WorkerAuthNonceValidityPeriod = 2 * time.Minute
)
