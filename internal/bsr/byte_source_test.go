// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package bsr_test

import (
	"testing"

	"github.com/hashicorp/boundary/internal/bsr"
	"github.com/stretchr/testify/assert"
)

func TestValidByteSource(t *testing.T) {
	cases := []struct {
		name string
		in   bsr.ByteSource
		want bool
	}{
		{
			bsr.Client.String(),
			bsr.Client,
			true,
		},
		{
			bsr.Server.String(),
			bsr.Server,
			true,
		},
		{
			bsr.UnknownByteSource.String(),
			bsr.UnknownByteSource,
			false,
		},
		{
			"something else",
			bsr.ByteSource(255),
			false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := bsr.ValidByteSource(tc.in)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestByteSourceString(t *testing.T) {
	cases := []struct {
		name string
		in   bsr.ByteSource
		want string
	}{
		{
			bsr.Client.String(),
			bsr.Client,
			"client",
		},
		{
			bsr.Server.String(),
			bsr.Server,
			"server",
		},
		{
			bsr.UnknownByteSource.String(),
			bsr.UnknownByteSource,
			"unknown bytesource",
		},
		{
			"something else",
			bsr.ByteSource(255),
			"unknown bytesource",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.in.String()
			assert.Equal(t, tc.want, got)
		})
	}
}
