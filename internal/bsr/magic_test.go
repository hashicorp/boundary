// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package bsr_test

import (
	"testing"

	"github.com/hashicorp/boundary/internal/bsr"
	"github.com/stretchr/testify/assert"
)

func TestMagic(t *testing.T) {
	assert.Equal(t, string(bsr.Magic), "\x89BSR\r\n\x1a\n")
	assert.Equal(t, bsr.Magic.Bytes(), []byte("\x89BSR\r\n\x1a\n"))
}
