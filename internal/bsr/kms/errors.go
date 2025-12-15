// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package kms

import (
	"errors"
)

// ErrUnknown represents an unknown error
var ErrUnknown = errors.New("unknown error")

// ErrInvalidParameter represents an invalid parameter error
var ErrInvalidParameter = errors.New("invalid parameter")

// ErrGenKey represents a key gen error
var ErrGenKey = errors.New("error occurred during key generation")

// ErrEncrypt represents an encryption error
var ErrEncrypt = errors.New("error occurred during encrypt")

// ErrDecrypt represents a decryption error
var ErrDecrypt = errors.New("error occurred during decrypt")

// ErrEncode represents an encoding error
var ErrEncode = errors.New("error occurred during encode")

// ErrDecode represents a decoding error
var ErrDecode = errors.New("error occurred during decode")

// ErrSign represents a signing error
var ErrSign = errors.New("error occurred during signing")
