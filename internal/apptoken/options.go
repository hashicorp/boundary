// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package apptoken

import (
	"context"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/util"
)

type options struct {
	withName               string
	withDescription        string
	withLimit              int
	withExpirationInterval uint32
	withReader             db.Reader
	withGrantScopeId       string
}

// Option - how options are passed as args
type Option func(*options) error

func getDefaultOptions() options {
	return options{}
}

func getOpts(opt ...Option) (options, error) {
	opts := getDefaultOptions()

	for _, o := range opt {
		if err := o(&opts); err != nil {
			return opts, err
		}
	}
	return opts, nil
}

// WithName provides an optional name.
func WithName(_ context.Context, n string) Option {
	return func(o *options) error {
		o.withName = n
		return nil
	}
}

// WithDescription provides an optional description.
func WithDescription(_ context.Context, desc string) Option {
	return func(o *options) error {
		o.withDescription = desc
		return nil
	}
}

// WithLimit provides an option to provide a limit.  Intentionally allowing
// negative integers.
func WithLimit(_ context.Context, limit int) Option {
	return func(o *options) error {
		o.withLimit = limit
		return nil
	}
}

// WithExpirationInterval provides an option to specify an expiration interval
// for an AppToken
func WithExpirationInterval(ctx context.Context, maxSeconds uint32) Option {
	const op = "apptoken.WithExpirationInterval"
	return func(o *options) error {
		switch {
		case maxSeconds == 0:
			return errors.New(ctx, errors.InvalidParameter, op, "invalid expiration interval (equal to zero)")
		}
		o.withExpirationInterval = maxSeconds
		return nil
	}
}

// withReader provides an option for specifying a reader to use for the
// operation.
func withReader(ctx context.Context, reader db.Reader) Option {
	const op = "apptoken.withReader"
	return func(o *options) error {
		switch {
		case util.IsNil(reader):
			return errors.New(ctx, errors.InvalidParameter, op, "missing reader")
		}
		o.withReader = reader
		return nil
	}
}

// WithGrantScopeId provides an option to specify the scope ID for the grants for
// an apptoken.
func WithGrantScopeId(_ context.Context, id string) Option {
	const op = "apptoken.WithGrantScopeId"
	return func(o *options) error {
		if o.withGrantScopeId == "" {
			o.withGrantScopeId = ""
		}
		o.withGrantScopeId = id
		return nil
	}
}
