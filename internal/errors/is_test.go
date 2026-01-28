// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package errors_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestError_IsUnique(t *testing.T) {
	t.Parallel()
	tests := []struct {
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
			in: &pgconn.PgError{
				Code: "23503",
			},
			want: false,
		},
		{
			name: "postgres-is-unique2",
			in: &pgconn.PgError{
				Code: "23505",
			},
			want: true,
		},
		{
			name: "CodeUnique",
			in:   errors.E(context.TODO(), errors.WithCode(errors.NotUnique)),
			want: true,
		},
		{
			name: "wrapped-pg-is-unique",
			in: errors.E(
				context.TODO(),
				errors.WithWrap(&pgconn.PgError{
					Code: "23505",
				}),
			),
			want: true,
		},
		{
			name: "RecordNotFound",
			in:   errors.E(context.TODO(), errors.WithCode(errors.RecordNotFound)),
			want: false,
		},
		{
			name: "conflicting-wrapped-code",
			in:   errors.E(context.TODO(), errors.WithCode(errors.NotNull), errors.WithWrap(errors.E(context.TODO(), errors.WithCode(errors.NotUnique)))),
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
	tests := []struct {
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
			in: &pgconn.PgError{
				Code: "23505",
			},
			want: false,
		},
		{
			name: "postgres-is-check-constraint",
			in: &pgconn.PgError{
				Code: "23514",
			},
			want: true,
		},
		{
			name: "ErrCodeCheckConstraint",
			in:   errors.E(context.TODO(), errors.WithCode(errors.CheckConstraint)),
			want: true,
		},
		{
			name: "wrapped-pg-is-check-constraint",
			in: errors.E(context.TODO(), errors.WithCode(errors.CheckConstraint),
				errors.WithWrap(&pgconn.PgError{
					Code: "23514",
				}),
			),
			want: true,
		},
		{
			name: "RecordNotFound",
			in:   errors.E(context.TODO(), errors.WithCode(errors.RecordNotFound)),
			want: false,
		},
		{
			name: "conflicting-wrapped-code",
			in:   errors.E(context.TODO(), errors.WithCode(errors.NotNull), errors.WithWrap(errors.E(context.TODO(), errors.WithCode(errors.CheckConstraint)))),
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
	tests := []struct {
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
			in: &pgconn.PgError{
				Code: "23505",
			},
			want: false,
		},
		{
			name: "postgres-is-check-constraint-not-not-null",
			in: &pgconn.PgError{
				Code: "23514",
			},
			want: false,
		},
		{
			name: "postgres-is-not-null",
			in: &pgconn.PgError{
				Code: "23502",
			},
			want: true,
		},
		{
			name: "ErrCodeNotNull",
			in:   errors.E(context.TODO(), errors.WithCode(errors.NotNull)),
			want: true,
		},
		{
			name: "wrapped-pg-is-not-null",
			in: errors.E(context.TODO(), errors.WithCode(errors.NotNull),
				errors.WithWrap(&pgconn.PgError{
					Code: "23502",
				}),
			),
			want: true,
		},
		{
			name: "RecordNotFound",
			in:   errors.E(context.TODO(), errors.WithCode(errors.RecordNotFound)),
			want: false,
		},
		{
			name: "conflicting-wrapped-code",
			in:   errors.E(context.TODO(), errors.WithCode(errors.CheckConstraint), errors.WithWrap(errors.E(context.TODO(), errors.WithCode(errors.NotNull)))),
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
	tests := []struct {
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
			in: &pgconn.PgError{
				Code: "23505",
			},
			want: false,
		},
		{
			name: "postgres-is-check-constraint-not-not-null",
			in: &pgconn.PgError{
				Code: "23514",
			},
			want: false,
		},
		{
			name: "postgres-is-missing-table",
			in: &pgconn.PgError{
				Code: "42P01",
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

func TestError_IsNotFoundError(t *testing.T) {
	tests := []struct {
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
			name: "not-found-error",
			in:   errors.E(context.TODO(), errors.WithCode(errors.RecordNotFound)),
			want: true,
		},
		{
			name: "std-err",
			in:   fmt.Errorf("std error"),
			want: false,
		},
		{
			name: "conflicting-wrapped-code",
			in:   errors.E(context.TODO(), errors.WithCode(errors.NotNull), errors.WithWrap(errors.E(context.TODO(), errors.WithCode(errors.RecordNotFound)))),
			want: false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			err := tt.in
			got := errors.IsNotFoundError(err)
			assert.Equal(tt.want, got)
		})
	}
}
