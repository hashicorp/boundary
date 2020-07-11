package scope

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_StringToScopeType(t *testing.T) {
	tests := []struct {
		name       string
		s          string
		want       Type
		wantPrefix string
	}{
		{
			name:       "global",
			s:          "global",
			want:       Global,
			wantPrefix: "global",
		},
		{
			name:       "org",
			s:          "org",
			want:       Org,
			wantPrefix: "o",
		},
		{
			name:       "proj",
			s:          "project",
			want:       Project,
			wantPrefix: "p",
		},
		{
			name:       "unknown",
			s:          "org",
			want:       Unknown,
			wantPrefix: "unknown",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			got := StringToScopeType(tt.s)
			assert.Equal(tt.want, got)
			assert.Equalf(tt.wantPrefix, got.Prefix(), "unexpected prefix for %s", tt.s)
		})
	}
}
