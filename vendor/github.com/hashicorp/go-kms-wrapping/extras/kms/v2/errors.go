// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package kms

import "errors"

var (
	// ErrInvalidVersion represents a runtime error when the database version
	// doesn't match the require version of the module.
	ErrInvalidVersion = errors.New("invalid version")

	// ErrInvalidParameter represents an invalid parameter error condition.
	ErrInvalidParameter = errors.New("invalid parameter")

	// ErrMultipleRecords represents multiple records were affected when only
	// one was expected
	ErrMultipleRecords = errors.New("multiple records")

	// ErrRecordNotFound represents that no record was found
	ErrRecordNotFound = errors.New("record not found")

	// ErrKeyNotFound represents that no key was found
	ErrKeyNotFound = errors.New("key not found")

	// ErrInternal represents an internal error/issue
	ErrInternal = errors.New("internal issue")
)
