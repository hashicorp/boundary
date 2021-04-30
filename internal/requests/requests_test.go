package requests

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_RequestContextFromCtx(t *testing.T) {
	t.Parallel()

	type input struct {
		name   string
		input  context.Context
		output *RequestContext
	}
	tests := []input{
		{
			name:   "not added",
			input:  context.Background(),
			output: &RequestContext{},
		},
		{
			name:   "added but empty",
			input:  NewRequestContext(context.Background()),
			output: &RequestContext{},
		},
		{
			name: "non-empty",
			input: func() context.Context {
				ctx := context.WithValue(context.Background(), ContextRequestInformationKey, &RequestContext{
					UserId: "u_foo",
				})
				return ctx
			}(),
			output: &RequestContext{UserId: "u_foo"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.output, RequestContextFromCtx(test.input))
		})
	}
}
