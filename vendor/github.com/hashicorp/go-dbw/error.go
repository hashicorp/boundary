// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package dbw

import "errors"

var (
	// ErrUnknown is an unknown/undefined error
	ErrUnknown = errors.New("unknown")

	// ErrInvalidParameter is an invalid parameter error
	ErrInvalidParameter = errors.New("invalid parameter")

	// ErrInternal is an internal error
	ErrInternal = errors.New("internal error")

	// ErrRecordNotFound is a not found record error
	ErrRecordNotFound = errors.New("record not found")

	// ErrMaxRetries is a max retries error
	ErrMaxRetries = errors.New("too many retries")

	// ErrInvalidFieldMask is an invalid field mask error
	ErrInvalidFieldMask = errors.New("invalid field mask")
)
