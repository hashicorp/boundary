package common

import "time"

// In the future we could make this configurable
const (
	// StatusInterval is the base duration used in the calculation of the random backoff
	// during the worker status report
	StatusInterval = 2 * time.Second

	// StatusTimeout is the timeout duration on status calls to the controller from
	// the worker
	StatusTimeout = 5 * time.Second
)
