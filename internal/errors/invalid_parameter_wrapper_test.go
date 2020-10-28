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
		name    string
		details []errors.ParamaterDetails
		opt     []errors.Option
		want    error
	}{
		{
			name: "all-options",
			details: []errors.ParamaterDetails{
				{Name: "alice", Description: "Shamir's favorite aunt"},
				{Name: "bob", Description: "Shamir's favorite uncle"},
			},
			opt: []errors.Option{
				errors.WithOp("alice.Bob"),
				errors.WithWrap(errors.ErrRecordNotFound), // will be ignored and always be errors.ErrInvalidParameter
				errors.WithMsg("test msg"),
			},
			want: &errors.InvalidParametersWrapper{
				Err: &errors.Err{
					Op:      "alice.Bob",
					Wrapped: errors.ErrInvalidParameter,
					Msg:     "test msg",
					Code:    errors.InvalidParameter,
				},
				Details: []errors.ParamaterDetails{
					{Name: "alice", Description: "Shamir's favorite aunt"},
					{Name: "bob", Description: "Shamir's favorite uncle"},
				},
			},
		},
		{
			name: "no-options",
			opt:  nil,
			want: &errors.InvalidParametersWrapper{
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
			err := errors.NewInvalidParametersWrapper(tt.details, tt.opt...)
			require.Error(err)
			assert.Equal(tt.want, err)

			var e *errors.InvalidParametersWrapper
			isErr := stderrors.As(err, &e)
			assert.True(isErr)

			isErr = stderrors.Is(err, errors.ErrInvalidParameter)
			assert.True(isErr)
		})
	}
}
