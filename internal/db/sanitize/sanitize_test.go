// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package sanitize

import "testing"

func TestString(t *testing.T) {
	tests := []struct {
		name string
		s    string
		want string
	}{
		{"no-special", "string", "string"},
		{"spaces", "string string", "string string"},
		{"leading-sentinel-start", "\ufffestring", "\ufffdstring"},
		{"mixed", "\ufffe\uffffstring\ufffestring\uffff", "\ufffd\ufffdstring\ufffdstring\ufffd"},
		{"only-sentinels", "\ufffe\uffff\ufffe\uffff", "\ufffd\ufffd\ufffd\ufffd"},
		{"empty-string", "", ""},
		{"with-invalid-utf8", "\xff\xfe", "\ufffd\ufffd"},
		{"with-invalid-utf8-and-sentinels", "\xce\ufffe\ufffd\xcc", "\ufffd\ufffd\ufffd\ufffd"},
		{"with-invalid-utf8-mixed", "\xcefoo\xccbar\uffffzoo", "\ufffdfoo\ufffdbar\ufffdzoo"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := String(tt.s); got != tt.want {
				t.Errorf("String() = %v, want %v", got, tt.want)
			}
		})
	}
}
