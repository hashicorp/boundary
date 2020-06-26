package scope

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_StringToScopeType(t *testing.T) {
	tests := []struct {
		name string
		s    string
		want Type
	}{
		{
			name: "org",
			s:    "organization",
			want: Organization,
		},
		{
			name: "proj",
			s:    "project",
			want: Project,
		},
		{
			name: "unknown",
			s:    "org",
			want: Unknown,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			got := StringToScopeType(tt.s)
			assert.Equal(tt.want, got)
		})
	}
}
