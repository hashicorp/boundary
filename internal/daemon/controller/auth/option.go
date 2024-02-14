// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package auth

import (
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/perms"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
)

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
	withScopeId                 string
	withPin                     string
	withId                      string
	withAction                  action.Type
	withType                    resource.Type
	withUserId                  string
	withKms                     *kms.Kms
	withRecoveryTokenNotAllowed bool
	withAnonymousUserNotAllowed bool
	withResource                *perms.Resource
}

func getDefaultOptions() options {
	return options{}
}

func WithScopeId(id string) Option {
	return func(o *options) {
		o.withScopeId = id
	}
}

func WithPin(pin string) Option {
	return func(o *options) {
		o.withPin = pin
	}
}

func WithId(id string) Option {
	return func(o *options) {
		o.withId = id
	}
}

func WithAction(action action.Type) Option {
	return func(o *options) {
		o.withAction = action
	}
}

func WithType(rt resource.Type) Option {
	return func(o *options) {
		o.withType = rt
	}
}

func WithUserId(id string) Option {
	return func(o *options) {
		o.withUserId = id
	}
}

func WithKms(kms *kms.Kms) Option {
	return func(o *options) {
		o.withKms = kms
	}
}

func WithRecoveryTokenNotAllowed(notAllowed bool) Option {
	return func(o *options) {
		o.withRecoveryTokenNotAllowed = notAllowed
	}
}

func WithAnonymousUserNotAllowed(notAllowed bool) Option {
	return func(o *options) {
		o.withAnonymousUserNotAllowed = notAllowed
	}
}

// WithResource specifies a resource to use
func WithResource(resource *perms.Resource) Option {
	return func(o *options) {
		o.withResource = resource
	}
}
