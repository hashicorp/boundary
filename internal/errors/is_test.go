package errors_test

import (
	"testing"

	"github.com/hashicorp/boundary/internal/errors"
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
		{
			name: "ErrCodeUnique",
			in:   errors.ErrNotUnique,
			want: true,
		},
		{
			name: "wrapped-pq-is-unique",
			in: errors.New(errors.NotUnique,
				errors.WithWrap(&pq.Error{
					Code: pq.ErrorCode("23505"),
				}),
			),
			want: true,
		},
		{
			name: "ErrRecordNotFound",
			in:   errors.ErrRecordNotFound,
			want: false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			err := tt.in
			got := errors.IsUniqueError(err)
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
		{
			name: "ErrCodeCheckConstraint",
			in:   errors.New(errors.CheckConstraint),
			want: true,
		},
		{
			name: "wrapped-pq-is-check-constraint",
			in: errors.New(errors.CheckConstraint,
				errors.WithWrap(&pq.Error{
					Code: pq.ErrorCode("23514"),
				}),
			),
			want: true,
		},
		{
			name: "ErrRecordNotFound",
			in:   errors.ErrRecordNotFound,
			want: false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			err := tt.in
			got := errors.IsCheckConstraintError(err)
			assert.Equal(tt.want, got)
		})
	}
}

func TestError_IsNotNullError(t *testing.T) {
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
			name: "postgres-is-unique-not-not-null",
			in: &pq.Error{
				Code: pq.ErrorCode("23505"),
			},
			want: false,
		},
		{
			name: "postgres-is-check-constraint-not-not-null",
			in: &pq.Error{
				Code: pq.ErrorCode("23514"),
			},
			want: false,
		},
		{
			name: "postgres-is-not-null",
			in: &pq.Error{
				Code: pq.ErrorCode("23502"),
			},
			want: true,
		},
		{
			name: "ErrCodeNotNull",
			in:   errors.New(errors.NotNull),
			want: true,
		},
		{
			name: "wrapped-pq-is-not-null",
			in: errors.New(errors.NotNull,
				errors.WithWrap(&pq.Error{
					Code: pq.ErrorCode("23502"),
				}),
			),
			want: true,
		},
		{
			name: "ErrRecordNotFound",
			in:   errors.ErrRecordNotFound,
			want: false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			err := tt.in
			got := errors.IsNotNullError(err)
			assert.Equal(tt.want, got)
		})
	}
}
