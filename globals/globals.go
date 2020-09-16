package globals

import "time"

// NOTE: Globals, in the traditional sense, are bad. But there are some
// situations where we want a value that is constant per invocation but
// invocation may be in various places, such as a test or via CLI, and placing
// such a value in any given package leads to import issues. So think of this
// package as "freeing us from circular dependency hell". These values should
// only ever be set at startup, but simply available to reference from anywhere.

const (
	TcpProxyV1     = "boundary-tcp-proxy-v1"
	ServiceTokenV1 = "s1"
)

type ContextMaxRequestSizeType int
type ContextOriginalRequestPathType int

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
)
