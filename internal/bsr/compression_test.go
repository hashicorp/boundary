// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package bsr_test

import (
	"testing"

	"github.com/hashicorp/boundary/internal/bsr"
	"github.com/stretchr/testify/assert"
)

func TestValidCompression(t *testing.T) {
	cases := []struct {
		name string
		in   bsr.Compression
		want bool
	}{
		{
			bsr.NoCompression.String(),
			bsr.NoCompression,
			true,
		},
		{
			bsr.GzipCompression.String(),
			bsr.GzipCompression,
			true,
		},
		{
			"something else",
			bsr.Compression(255),
			false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := bsr.ValidCompression(tc.in)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestCompressionString(t *testing.T) {
	cases := []struct {
		name string
		in   bsr.Compression
		want string
	}{
		{
			bsr.NoCompression.String(),
			bsr.NoCompression,
			"no compression",
		},
		{
			bsr.GzipCompression.String(),
			bsr.GzipCompression,
			"gzip",
		},
		{
			"something else",
			bsr.Compression(255),
			"unknown compression",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.in.String()
			assert.Equal(t, tc.want, got)
		})
	}
}
