// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package bsr_test

import (
	"testing"

	"github.com/hashicorp/boundary/internal/bsr"
	"github.com/stretchr/testify/assert"
)

func TestValidDirection(t *testing.T) {
	cases := []struct {
		name string
		in   bsr.Direction
		want bool
	}{
		{
			bsr.Inbound.String(),
			bsr.Inbound,
			true,
		},
		{
			bsr.Outbound.String(),
			bsr.Outbound,
			true,
		},
		{
			bsr.UnknownDirection.String(),
			bsr.UnknownDirection,
			false,
		},
		{
			"something else",
			bsr.Direction(255),
			false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := bsr.ValidDirection(tc.in)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestDirectionString(t *testing.T) {
	cases := []struct {
		name string
		in   bsr.Direction
		want string
	}{
		{
			bsr.Inbound.String(),
			bsr.Inbound,
			"inbound",
		},
		{
			bsr.Outbound.String(),
			bsr.Outbound,
			"outbound",
		},
		{
			bsr.UnknownDirection.String(),
			bsr.UnknownDirection,
			"unknown direction",
		},
		{
			"something else",
			bsr.Direction(255),
			"unknown direction",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.in.String()
			assert.Equal(t, tc.want, got)
		})
	}
}
