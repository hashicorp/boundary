// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package event

import (
	"fmt"

	"github.com/hashicorp/go-secure-stdlib/base62"
)

const IdPrefix = "e"

// NewId is a bit of a modified NewId has been done to stop a circular
// dependency with the errors package that is caused by importing
// boundary/internal/db
func NewId(prefix string) (string, error) {
	const op = "event.newId"
	if prefix == "" {
		return "", fmt.Errorf("%s: missing prefix: %w", op, ErrInvalidParameter)
	}
	var publicId string
	var err error

	publicId, err = base62.Random(10)
	if err != nil {
		return "", fmt.Errorf("%s: unable to generate id %v: %w", op, err, ErrIo)
	}
	return fmt.Sprintf("%s_%s", prefix, publicId), nil
}
