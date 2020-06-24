package db

import (
	"testing"

	"github.com/lib/pq"
	"github.com/stretchr/testify/assert"
)

func TestError_IsUnique(t *testing.T) {
	var tests = []struct {
		name string
		in   error
		want bool
	}{
		{
			name: "nil-error",
			in:   nil,
			want: false,
		},
		{
			name: "postgres-not-unique",
			in: &pq.Error{
				Code: pq.ErrorCode("23503"),
			},
			want: false,
		},
		{
			name: "postgres-is-unique2",
			in: &pq.Error{
				Code: pq.ErrorCode("23505"),
			},
			want: true,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			err := tt.in
			got := IsUniqueError(err)
			assert.Equal(tt.want, got)
		})
	}
}

func TestError_IsCheckConstraint(t *testing.T) {
	var tests = []struct {
		name string
		in   error
		want bool
	}{
		{
			name: "nil-error",
			in:   nil,
			want: false,
		},
		{
			name: "postgres-not-check-constraint",
			in: &pq.Error{
				Code: pq.ErrorCode("23505"),
			},
			want: false,
		},
		{
			name: "postgres-is-check-constraint",
			in: &pq.Error{
				Code: pq.ErrorCode("23514"),
			},
			want: true,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			err := tt.in
			got := IsCheckConstraintError(err)
			assert.Equal(tt.want, got)
		})
	}
}
