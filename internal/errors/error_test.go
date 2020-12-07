package errors_test

import (
	"context"
	stderrors "errors"
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_ErrorE(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		opt  []errors.Option
		want error
	}{
		{
			name: "all-options",
			opt: []errors.Option{
				errors.WithCode(errors.InvalidParameter),
				errors.WithOp("alice.Bob"),
				errors.WithWrap(errors.ErrRecordNotFound),
				errors.WithMsg("test msg"),
			},
			want: &errors.Err{
				Op:      "alice.Bob",
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
		{
			name: "withCode",
			opt: []errors.Option{
				errors.WithCode(errors.RecordNotFound),
			},
			want: &errors.Err{
				Code: errors.RecordNotFound,
			},
		},
		{
			name: "uses-wrapped-code",
			opt: []errors.Option{
				errors.WithWrap(errors.ErrRecordNotFound),
			},
			want: &errors.Err{
				Code:    errors.RecordNotFound,
				Wrapped: errors.ErrRecordNotFound,
			},
		},
		{
			name: "conflicting-withCode-withWrap",
			opt: []errors.Option{
				errors.WithCode(errors.InvalidFieldMask),
				errors.WithWrap(errors.ErrRecordNotFound),
			},
			want: &errors.Err{
				Code:    errors.InvalidFieldMask,
				Wrapped: errors.ErrRecordNotFound,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			err := errors.E(tt.opt...)
			require.Error(err)
			assert.Equal(tt.want, err)
		})
	}
}

func Test_NewError(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		code errors.Code
		op   errors.Op
		msg  string
		opt  []errors.Option
		want error
	}{
		{
			name: "all-options",
			code: errors.InvalidParameter,
			op:   "alice.Bob",
			msg:  "test msg",
			opt: []errors.Option{
				errors.WithWrap(errors.ErrRecordNotFound),
			},
			want: &errors.Err{
				Op:      "alice.Bob",
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
		{
			name: "conflicting-op",
			op:   "alice.Bob",
			opt: []errors.Option{
				errors.WithOp("bab.Op"),
			},
			want: &errors.Err{
				Op:   "alice.Bob",
				Code: errors.Unknown,
			},
		},
		{
			name: "conflicting-msg",
			msg:  "test msg",
			opt: []errors.Option{
				errors.WithMsg("dont use this message"),
			},
			want: &errors.Err{
				Msg:  "test msg",
				Code: errors.Unknown,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			err := errors.New(tt.code, tt.op, tt.msg, tt.opt...)
			require.Error(err)
			assert.Equal(tt.want, err)
		})
	}
}

func Test_WrapError(t *testing.T) {
	t.Parallel()
	testErr := errors.E(errors.WithCode(errors.InvalidParameter), errors.WithOp("alice.Bob"), errors.WithMsg("test msg"))
	tests := []struct {
		name string
		opt  []errors.Option
		err  error
		op   errors.Op
		want error
	}{
		{
			name: "boundary-error",
			err:  testErr,
			op:   "alice.Bob",
			opt: []errors.Option{
				errors.WithMsg("test msg"),
			},
			want: &errors.Err{
				Wrapped: testErr,
				Op:      "alice.Bob",
				Msg:     "test msg",
				Code:    errors.InvalidParameter,
			},
		},
		{
			name: "boundary-error-no-op",
			err:  testErr,
			opt: []errors.Option{
				errors.WithMsg("test msg"),
			},
			want: &errors.Err{
				Wrapped: testErr,
				Msg:     "test msg",
				Code:    errors.InvalidParameter,
			},
		},
		{
			name: "boundary-error-no-options",
			err:  testErr,
			want: &errors.Err{
				Wrapped: testErr,
				Code:    errors.InvalidParameter,
			},
		},
		{
			name: "std-error",
			err:  fmt.Errorf("std error"),
			want: &errors.Err{
				Wrapped: fmt.Errorf("std error"),
				Code:    errors.Unknown,
			},
		},
		{
			name: "conflicting-with-wrap",
			err:  testErr,
			opt: []errors.Option{
				errors.WithWrap(fmt.Errorf("dont wrap this error")),
			},
			want: &errors.Err{
				Wrapped: testErr,
				Code:    errors.InvalidParameter,
			},
		},
		{
			name: "conflicting-with-op",
			err:  testErr,
			op:   "alice.Bob",
			opt: []errors.Option{
				errors.WithOp("bad.Op"),
			},
			want: &errors.Err{
				Wrapped: testErr,
				Op:      "alice.Bob",
				Code:    errors.InvalidParameter,
			},
		},
		{
			name: "NotSpecificIntegrity",
			err: &pq.Error{
				Code:    pq.ErrorCode("23001"),
				Message: "test msg",
			},
			want: &errors.Err{
				Wrapped: errors.E(errors.WithCode(errors.NotSpecificIntegrity), errors.WithMsg("test msg")),
				Code:    errors.NotSpecificIntegrity,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			err := errors.Wrap(tt.err, tt.op, tt.opt...)
			require.Error(err)
			assert.Equal(tt.want, err)
		})
	}
}

func TestError_Info(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		err  *errors.Err
		want errors.Code
	}{
		{
			name: "nil",
			err:  nil,
			want: errors.Unknown,
		},
		{
			name: "Unknown",
			err:  errors.E().(*errors.Err),
			want: errors.Unknown,
		},
		{
			name: "InvalidParameter",
			err:  errors.E(errors.WithCode(errors.InvalidParameter)).(*errors.Err),
			want: errors.InvalidParameter,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			assert.Equal(tt.want.Info(), tt.err.Info())
		})
	}
}

func TestError_Error(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "msg",
			err:  errors.E(errors.WithMsg("test msg")),
			want: "test msg: unknown: error #0",
		},
		{
			name: "code",
			err:  errors.E(errors.WithCode(errors.CheckConstraint)),
			want: "constraint check failed, integrity violation: error #1000",
		},
		{
			name: "op-msg-and-code",
			err:  errors.E(errors.WithCode(errors.CheckConstraint), errors.WithOp("alice.bob"), errors.WithMsg("test msg")),
			want: "alice.bob: test msg: integrity violation: error #1000",
		},
		{
			name: "unknown",
			err:  errors.E(),
			want: "unknown, unknown: error #0",
		},
		{
			name: "wrapped-no-code",
			err:  errors.E(errors.WithWrap(errors.E(errors.WithCode(errors.InvalidParameter), errors.WithMsg("wrapped msg"))), errors.WithMsg("test msg")),
			want: "test msg: wrapped msg: parameter violation: error #100",
		},
		{
			name: "wrapped-different-error-codes",
			err:  errors.E(errors.WithCode(errors.CheckConstraint), errors.WithWrap(errors.E(errors.WithCode(errors.InvalidParameter), errors.WithMsg("wrapped msg"))), errors.WithMsg("test msg")),
			want: "test msg: integrity violation: error #1000: wrapped msg: parameter violation: error #100",
		},
		{
			name: "wrapped-same-error-codes",
			err:  errors.E(errors.WithCode(errors.CheckConstraint), errors.WithWrap(errors.E(errors.WithCode(errors.CheckConstraint), errors.WithMsg("wrapped msg"))), errors.WithMsg("test msg")),
			want: "test msg: wrapped msg: integrity violation: error #1000",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			got := tt.err.Error()
			assert.Equal(tt.want, got)
		})
	}
	t.Run("nil *Err", func(t *testing.T) {
		assert := assert.New(t)
		var err *errors.Err
		got := err.Error()
		assert.Equal("", got)
	})
}

func TestError_Unwrap(t *testing.T) {
	t.Parallel()
	testErr := errors.E(errors.WithMsg("test error"))

	tests := []struct {
		name      string
		err       error
		want      error
		wantIsErr error
	}{
		{
			name:      "ErrInvalidParameter",
			err:       errors.E(errors.WithWrap(errors.ErrInvalidParameter)),
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
			assert.True(errors.Is(tt.err, tt.wantIsErr))
		})
	}
	t.Run("nil *Err", func(t *testing.T) {
		assert := assert.New(t)
		var err *errors.Err
		got := err.Unwrap()
		assert.Equal(nil, got)
	})
}

func TestConvertError(t *testing.T) {
	t.Parallel()
	testErr := errors.E(errors.WithCode(errors.InvalidParameter), errors.WithOp("alice.Bob"), errors.WithMsg("test msg"))
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
		missingTable  = `select * from not_a_defined_table`
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
			wantErr: nil,
		},
		{
			name: "NotSpecificIntegrity",
			e: &pq.Error{
				Code: pq.ErrorCode("23001"),
			},
			wantErr: errors.E(errors.WithCode(errors.NotSpecificIntegrity)),
		},
		{
			name:    "convert-domain-error",
			e:       testErr,
			wantErr: testErr,
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
		assert.True(errors.Is(e, errors.ErrNotUnique))
		assert.Equal("Key (name)=(alice) already exists.: unique constraint violation: integrity violation: error #1002", e.Error())
	})
	t.Run("ErrCodeNotNull", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		_, err := rw.Exec(ctx, truncateTable, nil)
		require.NoError(err)
		_, err = rw.Exec(ctx, insert, []interface{}{"alice", nil, nil})
		require.Error(err)

		e := errors.Convert(err)
		require.NotNil(e)
		assert.True(errors.Is(e, errors.ErrNotNull))
		assert.Equal("description must not be empty: not null constraint violated: integrity violation: error #1001", e.Error())
	})
	t.Run("ErrCodeCheckConstraint", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		_, err := rw.Exec(ctx, truncateTable, nil)
		require.NoError(err)
		_, err = rw.Exec(ctx, insert, []interface{}{"alice", "coworker", "one"})
		require.Error(err)

		e := errors.Convert(err)
		require.NotNil(e)
		assert.True(errors.Is(e, errors.ErrCheckConstraint))
		assert.Equal("test_table_five_check constraint failed: check constraint violated: integrity violation: error #1000", e.Error())
	})
	t.Run("MissingTable", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		_, err := rw.Exec(ctx, missingTable, nil)
		require.Error(err)

		e := errors.Convert(err)
		require.NotNil(e)
		assert.True(errors.Match(errors.T(errors.MissingTable), e))
		assert.Equal("relation \"not_a_defined_table\" does not exist: integrity violation: error #1004", e.Error())
	})
}
