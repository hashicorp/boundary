// Copyright (c) Jim Lambert
// SPDX-License-Identifier: MIT

package gldap

import "errors"

var (
	// ErrUnknown is an unknown/undefined error
	ErrUnknown = errors.New("unknown")

	// ErrInvalidParameter is an invalid parameter error
	ErrInvalidParameter = errors.New("invalid parameter")

	// ErrInvalidState is an invalid state error
	ErrInvalidState = errors.New("invalid state")

	// ErrInternal is an internal error
	ErrInternal = errors.New("internal error")
)
