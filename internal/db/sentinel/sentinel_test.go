// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package sentinel

import (
	"testing"
)

func TestIs(t *testing.T) {
	tests := []struct {
		name string
		s    string
		want bool
	}{
		{"normal", "\ufffefoo\uffff", true},
		{"non-sentinel", "foo", false},
		{"trailing and leading start sentinel", "\ufffefoo\ufffe", false},
		{"trailing and leading end sentinel", "\uffffoo\uffff", false},
		{"only start sentinel with string", "\ufffefoo", false},
		{"only end sentinel with string", "foo\uffff", false},
		{"only end sentinel", "\uffff", false},
		{"only start sentinel", "\ufffe", false},
		{"sentinel with space before word", "\ufffe foo\uffff", true},
		{"sentinel with only spaces", "\ufffe  \uffff", true},
		{"sentinel with empty string", "\ufffe\uffff", true},
		{"multiple start sentinels with empty string", "\ufffe\ufffe  \uffff", true},
		{"multiple start sentinels", "\ufffe\ufffefoo\uffff", true},
		{"start sentinel space start sentinel space string", "\ufffe \ufffe foo \uffff", true},
		{"sentinel with space after word", "\ufffefoo   \uffff", true},
		{"multiple end sentinels with empty string", "\ufffe    \uffff\uffff\uffff", true},
		{"multiple end sentinels", "\ufffefoo\uffff\uffff\uffff", true},
		{"string space end sentinel space end sentinel", "\ufffefoo \uffff \uffff", true},
		{"only spaces", "  ", false},
		{"empty string", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Is(tt.s); got != tt.want {
				t.Errorf("Is() = %v, want %v", got, tt.want)
			}
		})
	}
}
