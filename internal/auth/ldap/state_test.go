// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ldap

import "testing"

func Test_validState(t *testing.T) {
	tests := []struct {
		s    string
		want bool
	}{
		{"bad", false},
		{"", false},
		{"unknown", false},
		{"inactive", true},
		{"active-private", true},
		{"active-public", true},
	}
	for _, tt := range tests {
		t.Run(tt.s, func(t *testing.T) {
			if got := validState(tt.s); got != tt.want {
				t.Errorf("validState() = %v, want %v", got, tt.want)
			}
		})
	}
}
