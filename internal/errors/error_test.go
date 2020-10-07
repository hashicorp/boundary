package errors

import (
	"errors"
	"testing"

	"github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
			in:   ErrNotUnique,
			want: true,
		},
		{
			name: "wrapped-pq-is-unique",
			in: NewError(
				WithWrap(&pq.Error{
					Code: pq.ErrorCode("23505"),
				}),
			),
			want: true,
		},
		{
			name: "ErrRecordNotFound",
			in:   ErrRecordNotFound,
			want: false,
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
		{
			name: "ErrCodeCheckConstraint",
			in:   NewError(WithErrCode(ErrCodeCheckConstraint)),
			want: true,
		},
		{
			name: "wrapped-pq-is-check-constraint",
			in: NewError(
				WithWrap(&pq.Error{
					Code: pq.ErrorCode("23514"),
				}),
			),
			want: true,
		},
		{
			name: "ErrRecordNotFound",
			in:   ErrRecordNotFound,
			want: false,
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
			in:   NewError(WithErrCode(ErrCodeNotNull)),
			want: true,
		},
		{
			name: "wrapped-pq-is-not-null",
			in: NewError(
				WithWrap(&pq.Error{
					Code: pq.ErrorCode("23502"),
				}),
			),
			want: true,
		},
		{
			name: "ErrRecordNotFound",
			in:   ErrRecordNotFound,
			want: false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			err := tt.in
			got := IsNotNullError(err)
			assert.Equal(tt.want, got)
		})
	}
}

func Test_NewError(t *testing.T) {
	tests := []struct {
		name string
		opt  []Option
		want error
	}{
		{
			name: "all-options",
			opt: []Option{
				WithWrap(ErrRecordNotFound),
				WithErrorMsg("test msg"),
				WithErrCode(ErrCodeInvalidParameter),
			},
			want: &Error{
				Wrapped: ErrRecordNotFound,
				Msg:     "test msg",
				Code:    func() *ErrCode { c := ErrCodeInvalidParameter; return &c }(),
			},
		},
		{
			name: "no-options",
			opt:  nil,
			want: &Error{
				Msg: "unknown error",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			err := NewError(tt.opt...)
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
			err:  NewError(WithErrorMsg("test msg")),
			want: "test msg",
		},
		{
			name: "code",
			err:  NewError(WithErrCode(ErrCodeCheckConstraint)),
			want: "constraint check failed: integrity violation",
		},
		{
			name: "msg-and-code",
			err:  NewError(WithErrorMsg("test msg"), WithErrCode(ErrCodeCheckConstraint)),
			want: "test msg",
		},
		{
			name: "unknown",
			err:  NewError(),
			want: "unknown error",
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
	testErr := NewError(WithErrorMsg("test error"))

	tests := []struct {
		name      string
		err       error
		want      error
		wantIsErr error
	}{
		{
			name:      "ErrInvalidParameter",
			err:       NewError(WithWrap(ErrInvalidParameter)),
			want:      ErrInvalidParameter,
			wantIsErr: ErrInvalidParameter,
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
}

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
