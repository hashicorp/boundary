// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package bsr

import (
	"errors"
)

var (
	// ErrUnknown represents an unknown error
	ErrUnknown = errors.New("unknown error")

	// ErrInvalidParameter represents an invalid parameter error
	ErrInvalidParameter = errors.New("invalid parameter")

	// ErrBsrKeyPersistenceFailure indicates a failure in persisting BSR encryption keys
	ErrBsrKeyPersistenceFailure = errors.New("could not persist BSR keys")

	// ErrSummaryUnavailable indicates a BSR summary is unavailable
	ErrSummaryUnavailable = errors.New("summary not available")

	// ErrSignatureVerification indicates a failure in verifying a signature
	ErrSignatureVerification = errors.New("could not verify signature")

	// ErrNotSupported represents an operation that is not supported for a
	// particular protocol.
	ErrNotSupported = errors.New("not supported by protocol")

	// ErrAlreadyRegistered is an error with registering functions.
	ErrAlreadyRegistered = errors.New("type already registered")

	// ErrEndChunkNotEmpty indicates a malformed END chunk.
	ErrEndChunkNotEmpty = errors.New("end chunk not empty")

	// ErrChunkDecode indicates an error when decoding a chunk.
	ErrChunkDecode = errors.New("error decoding chunk")

	// ErrInvalidMagic is used when a binary bsr file is missing the magic string.
	ErrInvalidMagic = errors.New("invalid magic string")

	// ErrChecksum indicates that a checksum did not match.
	ErrChecksum = errors.New("computed checksum did NOT match")

	// ErrTimestampDecode indicates an error decoding a timestamp
	ErrTimestampDecode = errors.New("error decoding timestamp")
)
