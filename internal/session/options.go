package session

import (
	"github.com/hashicorp/boundary/internal/db/timestamp"
)

// getOpts - iterate the inbound Options and return a struct
func getOpts(opt ...Option) options {
	opts := getDefaultOptions()
	for _, o := range opt {
		o(&opts)
	}
	return opts
}

// Option - how Options are passed as arguments
type Option func(*options)

// options = how options are represented
type options struct {
	withLimit          int
	withOrder          string
	withScopeId        string
	withUserId         string
	withExpirationTime *timestamp.Timestamp
	withTestTofu       []byte
}

func getDefaultOptions() options {
	return options{}
}

// WithLimit provides an option to provide a limit. Intentionally allowing
// negative integers. If WithLimit < 0, then unlimited results are returned. If
// WithLimit == 0, then default limits are used for results.
func WithLimit(limit int) Option {
	return func(o *options) {
		o.withLimit = limit
	}
}

// WithOrder allows specifying an order for returned values
func WithOrder(order string) Option {
	return func(o *options) {
		o.withOrder = order
	}
}

// WithScopeId allows specifying a scope ID criteria for the function.
func WithScopeId(scopeId string) Option {
	return func(o *options) {
		o.withScopeId = scopeId
	}
}

// WithUserId allows specifying a user ID criteria for the function.
func WithUserId(userId string) Option {
	return func(o *options) {
		o.withUserId = userId
	}
}

// WithExpirationTime allows specifying an expiration time for the session
func WithExpirationTime(exp *timestamp.Timestamp) Option {
	return func(o *options) {
		o.withExpirationTime = exp
	}
}

// WithTestTofu allows specifying a test tofu for a test session
func WithTestTofu(tofu []byte) Option {
	return func(o *options) {
		o.withTestTofu = tofu
	}
}
