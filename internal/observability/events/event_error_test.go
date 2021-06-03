package event

import (
	"testing"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_newError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		fromOp          Op
		e               error
		opts            []Option
		want            *err
		wantErrMatch    *errors.Template
		wantErrContains string
	}{
		{
			name:            "missing-op",
			e:               errors.New(errors.InvalidParameter, "missing-operation", "missing operation"),
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing operation",
		},
		{
			name:            "missing-error",
			fromOp:          Op("missing-error"),
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing error",
		},
		{
			name:   "valid-no-opts",
			fromOp: Op("valid-no-opts"),
			e:      errors.New(errors.InvalidParameter, "valid-no-opts", "valid no opts"),
			want: &err{
				Error:   errors.New(errors.InvalidParameter, "valid-no-opts", "valid no opts"),
				Version: ErrorVersion,
				Op:      Op("valid-no-opts"),
			},
		},
		{
			name:   "valid-all-opts",
			fromOp: Op("valid-all-opts"),
			e:      errors.New(errors.InvalidParameter, "valid-all-opts", "valid all opts"),
			opts: []Option{
				WithId("valid-all-opts"),
				WithRequestInfo(TestRequestInfo(t)),
			},
			want: &err{
				Error:       errors.New(errors.InvalidParameter, "valid-all-opts", "valid all opts"),
				Version:     ErrorVersion,
				Op:          Op("valid-all-opts"),
				Id:          "valid-all-opts",
				RequestInfo: TestRequestInfo(t),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := newError(tt.fromOp, tt.e, tt.opts...)
			if tt.wantErrMatch != nil {
				require.Error(err)
				assert.Nil(got)
				assert.True(errors.Match(tt.wantErrMatch, err))
				if tt.wantErrContains != "" {
					assert.Contains(err.Error(), tt.wantErrContains)
				}
				return
			}
			require.NoError(err)
			require.NotNil(got)
			opts := getOpts(tt.opts...)
			if opts.withId == "" {
				tt.want.Id = got.Id
			}
			if opts.withRequestInfo != nil {
				tt.want.RequestInfo = got.RequestInfo
			}
			assert.Equal(tt.want, got)
		})
	}

}

func Test_errvalidate(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name            string
		id              string
		op              Op
		wantErr         error
		wantErrMatch    *errors.Template
		wantErrContains string
	}{
		{
			name:            "missing-id",
			op:              Op("missing-id"),
			wantErr:         errors.New(errors.InvalidParameter, "missing-id", "missing id"),
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing id",
		},
		{
			name:            "missing-operation",
			id:              "missing-operation",
			wantErr:         errors.New(errors.InvalidParameter, "missing-operation", "missing operation"),
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing operation",
		},
		{
			name:    "valid",
			op:      Op("valid"),
			id:      "valid",
			wantErr: errors.New(errors.InvalidParameter, "valid", "valid error"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			e := err{
				Op:    tt.op,
				Id:    Id(tt.id),
				Error: tt.wantErr,
			}
			err := e.validate()
			if tt.wantErrMatch != nil {
				require.Error(err)
				assert.True(errors.Match(tt.wantErrMatch, err))
				if tt.wantErrContains != "" {
					assert.Contains(err.Error(), tt.wantErrContains)
				}
				return
			}
			assert.NoError(err)
			assert.Equal(tt.wantErr, e.Error)
		})
	}
}

func Test_errEventType(t *testing.T) {
	t.Parallel()
	e := &err{}
	assert.Equal(t, string(ErrorType), e.EventType())
}
