// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

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
