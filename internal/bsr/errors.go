// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package bsr

import (
	"errors"
)

// ErrUnknown represents an unknown error
var ErrUnknown = errors.New("unknown error")

// ErrInvalidParameter represents an invalid parameter error
var ErrInvalidParameter = errors.New("invalid parameter")

// ErrNotSupported represents an operation that is not supported for a
// particular protocol.
var ErrNotSupported = errors.New("not supported by protocol")

// ErrBsrKeyPersistenceFailure indicates a failure in persisting BSR encryption keys
var ErrBsrKeyPersistenceFailure = errors.New("could not persist BSR keys")

// ErrSummaryUnavailable indicates a BSR summary is unavailable
var ErrSummaryUnavailable = errors.New("summary not available")
