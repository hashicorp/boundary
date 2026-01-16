// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package session

import (
	"crypto/rand"
	"io"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/pagination"
	"github.com/hashicorp/boundary/internal/perms"
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
	withLimit                    int
	withOrderByCreateTime        db.OrderBy
	withProjectIds               []string
	withUserId                   string
	withExpirationTime           *timestamp.Timestamp
	withTestTofu                 []byte
	withSessionIds               []string
	withDbOpts                   []db.Option
	withWorkerStateDelay         time.Duration
	withTerminated               bool
	withPermissions              *perms.UserPermissions
	withIgnoreDecryptionFailures bool
	withRandomReader             io.Reader
	withStartPageAfterItem       pagination.Item
	withProxyCertificate         *ProxyCertificate
}

func getDefaultOptions() options {
	return options{
		withWorkerStateDelay: 10 * time.Second,
		withRandomReader:     rand.Reader,
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

// WithProjectIds allows specifying a project ID criteria for the function.
func WithProjectIds(projectIds []string) Option {
	return func(o *options) {
		o.withProjectIds = projectIds
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

// WithTerminated is used to include terminated sessions in a list request.
func WithTerminated(withTerminated bool) Option {
	return func(o *options) {
		o.withTerminated = withTerminated
	}
}

// WithPermissions is used to include user permissions when constructing a
// Repository.
func WithPermissions(p *perms.UserPermissions) Option {
	return func(o *options) {
		o.withPermissions = p
	}
}

// WithIgnoreDecryptionFailures is used to ignore decryption
// failures when doing lookups. This should be used sparingly.
// It is currently only used to allow a user to cancel a session
// in the presence of a undecryptable TOFU token.
func WithIgnoreDecryptionFailures(ignoreFailures bool) Option {
	return func(o *options) {
		o.withIgnoreDecryptionFailures = ignoreFailures
	}
}

// WithRandomReader is used to configure the random source
// to use when generating secrets. Defaults to crypto/rand.Reader.
func WithRandomReader(rand io.Reader) Option {
	return func(o *options) {
		o.withRandomReader = rand
	}
}

// WithStartPageAfterItem is used to paginate over the results.
// The next page will start after the provided item.
func WithStartPageAfterItem(item pagination.Item) Option {
	return func(o *options) {
		o.withStartPageAfterItem = item
	}
}

// WithProxyCertificate is used to associate a ProxyCertificate with a session.
func WithProxyCertificate(pc *ProxyCertificate) Option {
	return func(o *options) {
		o.withProxyCertificate = pc
	}
}
