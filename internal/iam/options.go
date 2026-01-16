// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package iam

import (
	"io"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/pagination"
)

// getOpts - iterate the inbound Options and return a struct
func getOpts(opt ...Option) options {
	opts := getDefaultOptions()
	for _, o := range opt {
		if o != nil {
			o(&opts)
		}
	}
	return opts
}

// Option - how Options are passed as arguments
type Option func(*options)

// options = how options are represented
type options struct {
	withPublicId                string
	withName                    string
	withDescription             string
	withLimit                   int
	withRecursive               bool
	withGrantScopeIds           []string
	withSkipVetForWrite         bool
	withDisassociate            bool
	withSkipAdminRoleCreation   bool
	withSkipDefaultRoleCreation bool
	withUserId                  string
	withRandomReader            io.Reader
	withAccountIds              []string
	withPrimaryAuthMethodId     string
	withReader                  db.Reader
	withWriter                  db.Writer
	withStartPageAfterItem      pagination.Item
}

func getDefaultOptions() options {
	return options{
		withPublicId:        "",
		withName:            "",
		withDescription:     "",
		withLimit:           0,
		withSkipVetForWrite: false,
		withRecursive:       false,
	}
}

// WithPublicId provides an optional public id
func WithPublicId(id string) Option {
	return func(o *options) {
		o.withPublicId = id
	}
}

// WithDescription provides an optional description
func WithDescription(desc string) Option {
	return func(o *options) {
		o.withDescription = desc
	}
}

// WithRecursive indicates that this request is a recursive request
func WithRecursive(isRecursive bool) Option {
	return func(o *options) {
		o.withRecursive = isRecursive
	}
}

// WithName provides an option to search by a friendly name
func WithName(name string) Option {
	return func(o *options) {
		o.withName = name
	}
}

// WithLimit provides an option to provide a limit.  Intentionally allowing
// negative integers.   If WithLimit < 0, then unlimited results are returned.
// If WithLimit == 0, then default limits are used for results.
func WithLimit(limit int) Option {
	return func(o *options) {
		o.withLimit = limit
	}
}

// WithGrantScopeIds provides an option to specify the scope ID for grants in
// roles. In most tests this is likely the option to use, however, for tests
// that call repo functions instead of test functions the other option is still
// correct to specify a grant scope at creation time.
func WithGrantScopeIds(ids []string) Option {
	return func(o *options) {
		o.withGrantScopeIds = ids
	}
}

// WithSkipVetForWrite provides an option to allow skipping vet checks to allow
// testing lower-level SQL triggers and constraints
func WithSkipVetForWrite(enable bool) Option {
	return func(o *options) {
		o.withSkipVetForWrite = enable
	}
}

// WithDisassociate provides an option to allow the combining of disassociating
// and associating a user in one operation.
func WithDisassociate(enable bool) Option {
	return func(o *options) {
		o.withDisassociate = enable
	}
}

// WithSkipAdminRoleCreation provides an option to disable the automatic
// creation of an admin role when a new scope is created.
func WithSkipAdminRoleCreation(enable bool) Option {
	return func(o *options) {
		o.withSkipAdminRoleCreation = enable
	}
}

// WithSkipDefaultRoleCreation provides an option to disable the automatic
// creation of a default role when a new scope is created.
func WithSkipDefaultRoleCreation(enable bool) Option {
	return func(o *options) {
		o.withSkipDefaultRoleCreation = enable
	}
}

// WithUserId provides an option to specify the user ID to use when creating roles with new scopes.
func WithUserId(id string) Option {
	return func(o *options) {
		o.withUserId = id
	}
}

// WithRandomReader provides an option to specify a random reader.
func WithRandomReader(reader io.Reader) Option {
	return func(o *options) {
		o.withRandomReader = reader
	}
}

// WithAccountIds provides an option for specifying account ids to
// add to a user.
func WithAccountIds(id ...string) Option {
	return func(o *options) {
		o.withAccountIds = id
	}
}

// WithPrimaryAuthMethodId provides an option to specify the
// primary auth method for the scope.
func WithPrimaryAuthMethodId(id string) Option {
	return func(o *options) {
		o.withPrimaryAuthMethodId = id
	}
}

// WithReaderWriter allows the caller to pass an inflight transaction to be used
// for all database operations. If WithReaderWriter(...) is used, then the
// caller is responsible for managing the transaction. The purpose of the
// WithReaderWriter(...) option is to allow the caller to create the scope and
// all of its keys in the same transaction.
func WithReaderWriter(r db.Reader, w db.Writer) Option {
	return func(o *options) {
		o.withReader = r
		o.withWriter = w
	}
}

// WithStartPageAfterItem is used to paginate over the results.
// The next page will start after the provided item.
func WithStartPageAfterItem(item pagination.Item) Option {
	return func(o *options) {
		o.withStartPageAfterItem = item
	}
}
