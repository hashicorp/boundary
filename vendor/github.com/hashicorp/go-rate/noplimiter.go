// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package rate

import "net/http"

type nopLimiter struct{}

// SetPolicyHeader is a noop.
func (*nopLimiter) SetPolicyHeader(_, _ string, _ http.Header) error { return nil }

// SetUsageHeader is a noop.
func (*nopLimiter) SetUsageHeader(_ *Quota, _ http.Header) { return }

// Allow will always allow.
func (*nopLimiter) Allow(_, _, _, _ string) (bool, *Quota, error) {
	return true, nil, nil
}

// Shutdown is a noop.
func (*nopLimiter) Shutdown() error { return nil }

// NopLimiter can be used in the place of a Limiter when no limits need to be
// enforced, but a Limiter is expected.
var NopLimiter *nopLimiter

type limiter interface {
	SetPolicyHeader(string, string, http.Header) error
	SetUsageHeader(*Quota, http.Header)
	Allow(string, string, string, string) (bool, *Quota, error)
	Shutdown() error
}

// Ensure that both NopLimiter and Limiter match the same interface.
var (
	_ limiter = NopLimiter
	_ limiter = (*Limiter)(nil)
)
