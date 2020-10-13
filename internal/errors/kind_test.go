package errors

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestKind_String(t *testing.T) {
	tests := []struct {
		name string
		e    Kind
		want string
	}{
		{
			name: "Other",
			e:    Other,
			want: "unknown",
		},
		{
			name: "Parameter",
			e:    Parameter,
			want: "parameter violation",
		},
		{
			name: "Integrity",
			e:    Integrity,
			want: "integrity violation",
		},
		{
			name: "Search",
			e:    Search,
			want: "search issue",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			got := tt.e.String()
			assert.Equal(tt.want, got)
		})
	}
}
