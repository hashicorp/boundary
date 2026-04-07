// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package convert

import "errors"

// Common convert errors.
var (
	ErrUnsupportedProtocol = errors.New("unsupported protocol")
	ErrMalformedBsr        = errors.New("malformed bsr data file")
)
