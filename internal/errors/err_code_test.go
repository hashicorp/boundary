package errors

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestErrClass_String(t *testing.T) {
	tests := []struct {
		name string
		e    ErrClass
		want string
	}{
		{
			name: "UnknownErrClass",
			e:    UnknownErrClass,
			want: "unknown",
		},
		{
			name: "ParameterError",
			e:    ParameterError,
			want: "parameter violation",
		},
		{
			name: "IntegrityError",
			e:    IntegrityError,
			want: "integrity violation",
		},
		{
			name: "SearchError",
			e:    SearchError,
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
