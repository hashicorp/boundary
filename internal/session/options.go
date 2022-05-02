package session

import (
	"time"

	"github.com/hashicorp/boundary/internal/db"
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
	withLimit                       int
	withOrderByCreateTime           db.OrderBy
	withScopeIds                    []string
	withUserId                      string
	withExpirationTime              *timestamp.Timestamp
	withTestTofu                    []byte
	withListingConvert              bool
	withSessionIds                  []string
	withWorkerId                    string
	withDbOpts                      []db.Option
	withWorkerStateDelay            time.Duration
	withDeadWorkerConnCloseMinGrace time.Duration
}

func getDefaultOptions() options {
	return options{
		withWorkerStateDelay: 10 * time.Second,
	}
}

// WithLimit provides an option to provide a limit. Intentionally allowing
// negative integers. If WithLimit < 0, then unlimited results are returned. If
// WithLimit == 0, then default limits are used for results.
func WithLimit(limit int) Option {
	return func(o *options) {
		o.withLimit = limit
	}
}

// WithOrderByCreateTime provides an option to specify ordering by the
// CreateTime field.
func WithOrderByCreateTime(orderBy db.OrderBy) Option {
	return func(o *options) {
		o.withOrderByCreateTime = orderBy
	}
}

// WithScopeIds allows specifying a scope ID criteria for the function.
func WithScopeIds(scopeIds []string) Option {
	return func(o *options) {
		o.withScopeIds = scopeIds
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

// WithSessionIds allows the specification of the session ids to use for the
// operation.
func WithSessionIds(ids ...string) Option {
	return func(o *options) {
		o.withSessionIds = ids
	}
}

func withListingConvert(withListingConvert bool) Option {
	return func(o *options) {
		o.withListingConvert = withListingConvert
	}
}

// WithWorkerId allows the specification of the worker id to use
func WithWorkerId(id string) Option {
	return func(o *options) {
		o.withWorkerId = id
	}
}

// WithDbOpts passes through given DB options to the DB layer
func WithDbOpts(opts ...db.Option) Option {
	return func(o *options) {
		o.withDbOpts = opts
	}
}

// WithWorkerStateDelay is used by queries to account for a delay in state
// propagation between worker and controller.
func WithWorkerStateDelay(d time.Duration) Option {
	return func(o *options) {
		o.withWorkerStateDelay = d
	}
}
