package errors_test

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestError_IsUnique(t *testing.T) {
	t.Parallel()
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
			in: errors.E(errors.NotUnique,
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
	t.Parallel()
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
			in:   errors.E(errors.CheckConstraint),
			want: true,
		},
		{
			name: "wrapped-pq-is-check-constraint",
			in: errors.E(errors.CheckConstraint,
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
	t.Parallel()
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
			in:   errors.E(errors.NotNull),
			want: true,
		},
		{
			name: "wrapped-pq-is-not-null",
			in: errors.E(errors.NotNull,
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

func TestError_IsMissingTableError(t *testing.T) {
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
			name: "postgres-is-missing-table",
			in: &pq.Error{
				Code: pq.ErrorCode("42P01"),
			},
			want: true,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			err := tt.in
			got := errors.IsMissingTableError(err)
			assert.Equal(tt.want, got)
		})
	}
	t.Run("query-missing-table", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		conn, _ := db.TestSetup(t, "postgres")
		rw := db.New(conn)
		_, err := rw.Query(context.Background(), "select * from non_existent_table", nil)
		require.Error(err)
		assert.True(errors.IsMissingTableError(err))
	})
}
