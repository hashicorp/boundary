// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package bsr_test

import (
	"testing"

	"github.com/hashicorp/boundary/internal/bsr"
	"github.com/stretchr/testify/assert"
)

func TestValidEncrpytion(t *testing.T) {
	cases := []struct {
		name string
		in   bsr.Encryption
		want bool
	}{
		{
			bsr.NoEncryption.String(),
			bsr.NoEncryption,
			true,
		},
		{
			"something else",
			bsr.Encryption(255),
			false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := bsr.ValidEncryption(tc.in)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestEncryptionString(t *testing.T) {
	cases := []struct {
		name string
		in   bsr.Encryption
		want string
	}{
		{
			bsr.NoEncryption.String(),
			bsr.NoEncryption,
			"no encryption",
		},
		{
			"something else",
			bsr.Encryption(255),
			"unknown encryption",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.in.String()
			assert.Equal(t, tc.want, got)
		})
	}
}
