package errors_test

import (
	stderrors "errors"
	"testing"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_NewInvalidParameterWrapper(t *testing.T) {
	type args struct {
	}
	tests := []struct {
		name                 string
		parameterName        string
		parameterDescription string
		opt                  []errors.Option
		want                 error
	}{
		{
			name:                 "all-options",
			parameterName:        "alice",
			parameterDescription: "Shamir's favorite aunt",
			opt: []errors.Option{
				errors.WithOp("alice.Bob"),
				errors.WithWrap(errors.ErrRecordNotFound), // will be ignored and always be errors.ErrInvalidParameter
				errors.WithMsg("test msg"),
			},
			want: &errors.InvalidParameterWrapper{
				Err: &errors.Err{
					Op:      "alice.Bob",
					Wrapped: errors.ErrInvalidParameter,
					Msg:     "test msg",
					Code:    errors.InvalidParameter,
				},
				Name:        "alice",
				Description: "Shamir's favorite aunt",
			},
		},
		{
			name: "no-options",
			opt:  nil,
			want: &errors.InvalidParameterWrapper{
				Err: &errors.Err{
					Code:    errors.InvalidParameter,
					Wrapped: errors.ErrInvalidParameter,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			err := errors.NewInvalidParameterWrapper(tt.parameterName, tt.parameterDescription, tt.opt...)
			require.Error(err)
			assert.Equal(tt.want, err)

			var e *errors.InvalidParameterWrapper
			isErr := stderrors.As(err, &e)
			assert.True(isErr)

			isErr = stderrors.Is(err, errors.ErrInvalidParameter)
			assert.True(isErr)
		})
	}
}
