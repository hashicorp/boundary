// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package temperror

// tempError is an error that satisfies the temporary error interface that is
// internally used by gRPC and some Go stdlib code to determine whether an error
// should cause a listener to die. Any error that isn't an accept error is
// wrapped in this since one connection failing TLS wise doesn't mean we don't
// want to accept any more...
type tempError struct {
	error
}

// New creates aa "temporary" error wrapping the given error
func New(inner error) tempError {
	return tempError{error: inner}
}

// Temporary satisfies the necessary interface
func (t tempError) Temporary() bool {
	return true
}
