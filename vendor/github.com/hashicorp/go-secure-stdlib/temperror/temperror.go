// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package temperror

// tempError is an error that satisfies the temporary error interface that is
// internally used by gRPC and some Go stdlib code to determine whether an error
// should cause a listener to die.
//
// This was deprecated in Go
// (https://cs.opensource.google/go/go/+/a53e3d5f885ca7a0df1cd6cf65faa5b63a802dce)
// but it is still used in places in gRPC; it can also be used for internal
// signaling purposes.
type tempError struct {
	error
}

// New creates a "temporary" error wrapping the given error
func New(inner error) tempError {
	return tempError{error: inner}
}

// Temporary satisfies the necessary interface
func (t tempError) Temporary() bool {
	return true
}

// IsTempError returns whether it is a temporary error to avoid having to use it
// as it is in the gRPC source code, e.g.:
//
//	if ne, ok := err.(interface{ Temporary() bool }); !ok || !ne.Temporary() {
//
// This function does that for you :-)
func IsTempError(err error) bool {
	if ne, ok := err.(interface{ Temporary() bool }); !ok || !ne.Temporary() {
		return false
	}
	return true
}
