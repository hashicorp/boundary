// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package bsr_test

import (
	"testing"

	"github.com/hashicorp/boundary/internal/bsr"
	"github.com/stretchr/testify/assert"
)

func TestValidProtocol(t *testing.T) {
	cases := []struct {
		name string
		in   bsr.Protocol
		want bool
	}{
		{
			"Valid",
			bsr.Protocol("VALI"),
			true,
		},
		{
			"Invalid",
			bsr.Protocol("INVALID"),
			false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := bsr.ValidProtocol(tc.in)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestToText(t *testing.T) {
	cases := []struct {
		name string
		in   bsr.Protocol
		want string
	}{
		{
			"all ascii",
			bsr.Protocol("BOOM"),
			"BOOM",
		},
		{
			"not all ascii",
			bsr.Protocol("SSH\x87"),
			"SSH",
		},
		{
			"mostly not ascii",
			bsr.Protocol("S\x89\x99\x87"),
			"S",
		},
		{
			"no ascii",
			bsr.Protocol("\x95\x89\x99\x87"),
			"",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.in.ToText()
			assert.Equal(t, tc.want, got)
		})
	}
}
