// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package event

import (
	"errors"
)

var (
	ErrInvalidParameter = errors.New("invalid parameter")
	ErrMaxRetries       = errors.New("too many retries")
	ErrIo               = errors.New("error during io operation")
	ErrRecordNotFound   = errors.New("record not found")
	// ErrInvalidOperation represents an error when an operation cannot be completed
	// because the thing being operated on is in an invalid state
	ErrInvalidOperation = errors.New("invalid operation")
)
