// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package convert

import "errors"

// Common convert errors.
var (
	ErrUnsupportedProtocol = errors.New("unsupported protocol")
	ErrMalformedBsr        = errors.New("malformed bsr data file")
)
