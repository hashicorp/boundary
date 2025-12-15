// Copyright IBM Corp. 2020, 2025
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
	withScopeId                       string
	withPin                           string
	withId                            string
	withAction                        action.Type
	withUserId                        string
	withKms                           *kms.Kms
	withRecursive                     bool
	withRecoveryTokenNotAllowed       bool
	withAnonymousUserNotAllowed       bool
	withResource                      *perms.Resource
	withActions                       []string
	withFetchAdditionalResourceGrants []resource.Type
}

func getDefaultOptions() options {
	return options{}
}

func WithRecursive(isRecursive bool) Option {
	return func(o *options) {
		o.withRecursive = isRecursive
	}
}

// WithFetchAdditionalResourceGrants allows auth.Verify to fetch grants for additional resources to build a more
// complete GrantTuples of the requesting identity. This ensures that we can accurately determine
// authorized_action and authorized_collection_action for sub-resources
// E.g. Reading 'host-catalog' should also fetch authorized actions for 'hosts'
func WithFetchAdditionalResourceGrants(resources ...resource.Type) Option {
	return func(o *options) {
		o.withFetchAdditionalResourceGrants = append(o.withFetchAdditionalResourceGrants, resources...)
	}
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

// WithActions specifies a list of actions in the request
func WithActions(actions []string) Option {
	return func(o *options) {
		o.withActions = actions
	}
}
