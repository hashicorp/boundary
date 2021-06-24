package db

import (
	"testing"
)

func TestPrefix(t *testing.T) {
	tests := []struct {
		name string
		s    string
		want string
	}{
		{
			name: "no-sentinel",
			s:    "string",
			want: "\ufffestring",
		},
		{
			name: "already-has-sentinel",
			s:    "\ufffestring",
			want: "\ufffestring",
		},
		{
			name: "empty-string",
			s:    "",
			want: "",
		},
		{
			name: "space",
			s:    " ",
			want: "\ufffe ",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Prefix(tt.s); got != tt.want {
				t.Errorf("Prefix() = %v, want %v", got, tt.want)
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

func TestStrip(t *testing.T) {
	tests := []struct {
		name string
		s    string
		want string
	}{
		{
			name: "no-sentinel",
			s:    "string",
			want: "string",
		},
		{
			name: "has-sentinel",
			s:    "\ufffestring",
			want: "string",
		},
		{
			name: "space",
			s:    "\ufffe ",
			want: " ",
		},
		{
			name: "empty-string",
			s:    "",
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Strip(tt.s); got != tt.want {
				t.Errorf("Strip() = %v, want %v", got, tt.want)
			}
		})
	}
}
