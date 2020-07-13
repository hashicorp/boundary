package globals

import "time"

// NOTE:
// Globals are bad. But there are some situations where we want a value that is
// constant per invocation but invocation may be in various places, such as a
// test or via CLI, and placing such a value in any given package leads to
// import issues. These values should only ever be set at startup, but simply
// available to reference from anywhere.

const (
	ContextUserIdValue = "wt_user_id"
)

var (
	// DefaultMaxRequestDuration is the amount of time we'll wait for a request
	DefaultMaxRequestDuration = 90 * time.Second

	// DefaultMaxRequestSize is the maximum size of a request we allow by default
	DefaultMaxRequestSize = int64(1024 * 1024)
)
