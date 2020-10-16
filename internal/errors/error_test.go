package errors_test

import (
	"context"
	stderrors "errors"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_NewError(t *testing.T) {
	tests := []struct {
		name string
		code errors.Code
		opt  []errors.Option
		want error
	}{
		{
			name: "all-options",
			code: errors.InvalidParameter,
			opt: []errors.Option{
				errors.WithWrap(errors.ErrRecordNotFound),
				errors.WithMsg("test msg"),
			},
			want: &errors.Err{
				Wrapped: errors.ErrRecordNotFound,
				Msg:     "test msg",
				Code:    errors.InvalidParameter,
			},
		},
		{
			name: "no-options",
			opt:  nil,
			want: &errors.Err{
				Code: errors.Unknown,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			err := errors.New(tt.code, tt.opt...)
			require.Error(err)
			assert.Equal(tt.want, err)
		})
	}
}

func TestError_Error(t *testing.T) {

	tests := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "msg",
			err:  errors.New(errors.Unknown, errors.WithMsg("test msg")),
			want: "test msg: unknown: error #0",
		},
		{
			name: "code",
			err:  errors.New(errors.CheckConstraint),
			want: "constraint check failed, integrity violation: error #1000",
		},
		{
			name: "op-msg-and-code",
			err:  errors.New(errors.CheckConstraint, errors.WithOp("alice.bob"), errors.WithMsg("test msg")),
			want: "alice.bob: test msg: integrity violation: error #1000",
		},
		{
			name: "unknown",
			err:  errors.New(errors.Unknown),
			want: "unknown, unknown: error #0",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			got := tt.err.Error()
			assert.Equal(tt.want, got)
		})
	}
}

func TestError_Unwrap(t *testing.T) {
	t.Parallel()
	testErr := errors.New(errors.Unknown, errors.WithMsg("test error"))

	tests := []struct {
		name      string
		err       error
		want      error
		wantIsErr error
	}{
		{
			name:      "ErrInvalidParameter",
			err:       errors.New(errors.InvalidParameter, errors.WithWrap(errors.ErrInvalidParameter)),
			want:      errors.ErrInvalidParameter,
			wantIsErr: errors.ErrInvalidParameter,
		},
		{
			name:      "testErr",
			err:       testErr,
			want:      nil,
			wantIsErr: testErr,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			err := tt.err.(interface {
				Unwrap() error
			}).Unwrap()
			assert.Equal(tt.want, err)
			assert.True(stderrors.Is(tt.err, tt.wantIsErr))
		})
	}
}

func TestConvertError(t *testing.T) {
	const (
		createTable = `
	create table if not exists test_table (
	  id bigint generated always as identity primary key,
	  name text unique,
	  description text not null,
	  five text check(length(trim(five)) > 5)
	);
	`
		truncateTable = `truncate test_table;`
		insert        = `insert into test_table(name, description, five) values (?, ?, ?)`
	)
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)

	_, err := rw.Exec(ctx, createTable, nil)
	require.NoError(t, err)

	tests := []struct {
		name    string
		e       error
		wantErr error
	}{
		{
			name:    "nil",
			e:       nil,
			wantErr: nil,
		},
		{
			name:    "not-convertible",
			e:       stderrors.New("test error"),
			wantErr: stderrors.New("test error"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			err := errors.Convert(tt.e)
			if tt.wantErr == nil {
				assert.Nil(err)
				return
			}
			require.NotNil(err)
			assert.Equal(tt.wantErr, err)
		})
	}
	t.Run("ErrCodeUnique", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		_, err := rw.Exec(ctx, truncateTable, nil)
		require.NoError(err)
		_, err = rw.Exec(ctx, insert, []interface{}{"alice", "coworker", nil})
		require.NoError(err)
		_, err = rw.Exec(ctx, insert, []interface{}{"alice", "dup coworker", nil})
		require.Error(err)

		e := errors.Convert(err)
		require.NotNil(e)
		assert.True(stderrors.Is(e, errors.ErrNotUnique))
		assert.Equal("Key (name)=(alice) already exists.: integrity violation: error #1002: \nunique constraint violation: integrity violation: error #1002", e.Error())
	})
	t.Run("ErrCodeNotNull", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		_, err := rw.Exec(ctx, truncateTable, nil)
		require.NoError(err)
		_, err = rw.Exec(ctx, insert, []interface{}{"alice", nil, nil})
		require.Error(err)

		e := errors.Convert(err)
		require.NotNil(e)
		assert.True(stderrors.Is(e, errors.ErrNotNull))
		assert.Equal("description must not be empty: integrity violation: error #1001: \nnot null constraint violated: integrity violation: error #1001", e.Error())
	})
	t.Run("ErrCodeCheckConstraint", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		_, err := rw.Exec(ctx, truncateTable, nil)
		require.NoError(err)
		conn.LogMode(true)
		_, err = rw.Exec(ctx, insert, []interface{}{"alice", "coworker", "one"})
		require.Error(err)

		e := errors.Convert(err)
		require.NotNil(e)
		assert.True(stderrors.Is(e, errors.ErrCheckConstraint))
		assert.Equal("test_table_five_check constraint failed: integrity violation: error #1000: \ncheck constraint violated: integrity violation: error #1000", e.Error())
	})
}
