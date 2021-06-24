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
		{"trailing start sentinel", "\ufffefoo\ufffe", false},
		{"leading end sentinel", "\ufffffoo\uffff", false},
		{"sentinel with space before word", "\ufffe foo\uffff", true},
		{"sentinel with empty string", "\ufffe  \uffff", false},
		{"multiple start sentinels with empty string", "\ufffe\ufffe  \uffff", false},
		{"multiple start sentinels", "\ufffe\ufffefoo\uffff", true},
		{"start sentinel space start sentinel space string", "\ufffe \ufffe foo \uffff", true},
		{"sentinel with space after word", "\ufffefoo   \uffff", true},
		{"multiple end sentinels with empty string", "\ufffe    \uffff\uffff\uffff", false},
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

func TestSanitize(t *testing.T) {
	tests := []struct {
		name string
		s    string
		want string
	}{
		{
			name: "no-special",
			s:    "string",
			want: "string",
		},
		{
			name: "spaces",
			s:    "string string",
			want: "string string",
		},
		{
			name: "leading-sentinel",
			s:    "\ufffestring",
			want: "\ufffdstring",
		},
		{
			name: "with-sentinel",
			s:    "string \ufffe string",
			want: "string \ufffd string",
		},
		{
			name: "multiple-sentinels",
			s:    "\ufffestring\ufffestring\ufffe",
			want: "\ufffdstring\ufffdstring\ufffd",
		},
		{
			name: "leading-not-a-char",
			s:    "\uffffstring",
			want: "\ufffdstring",
		},
		{
			name: "with-not-a-char",
			s:    "string \uffff string",
			want: "string \ufffd string",
		},
		{
			name: "mixed",
			s:    "\ufffe\uffffstring\ufffestring\uffff",
			want: "\ufffd\ufffdstring\ufffdstring\ufffd",
		},
		{
			name: "empty-string",
			s:    "",
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Sanitize(tt.s); got != tt.want {
				t.Errorf("Sanitize() = %v, want %v", got, tt.want)
			}
		})
	}
}
