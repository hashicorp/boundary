package event

import (
	"fmt"
	"testing"

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
		wantErrIs       error
		wantErrContains string
	}{
		{
			name:            "missing-op",
			e:               fmt.Errorf("%s, missing operation: %w", "missing-operation", ErrInvalidParameter),
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing operation",
		},
		{
			name:            "missing-error",
			fromOp:          Op("missing-error"),
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing error",
		},
		{
			name:   "valid-no-opts",
			fromOp: Op("valid-no-opts"),
			e:      fmt.Errorf("%s: valid no opts: %w", "valid-no-opts", ErrInvalidParameter),
			want: &err{
				Error:   fmt.Errorf("%s: valid no opts: %w", "valid-no-opts", ErrInvalidParameter),
				Version: errorVersion,
				Op:      Op("valid-no-opts"),
			},
		},
		{
			name:   "valid-all-opts",
			fromOp: Op("valid-all-opts"),
			e:      fmt.Errorf("%s: valid all opts: %w", "valid-all-opts", ErrInvalidParameter),
			opts: []Option{
				WithId("valid-all-opts"),
				WithRequestInfo(TestRequestInfo(t)),
				WithInfo(map[string]interface{}{"msg": "hello"}),
			},
			want: &err{
				Error:       fmt.Errorf("%s: valid all opts: %w", "valid-all-opts", ErrInvalidParameter),
				Version:     errorVersion,
				Op:          Op("valid-all-opts"),
				Id:          "valid-all-opts",
				RequestInfo: TestRequestInfo(t),
				Info:        map[string]interface{}{"msg": "hello"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := newError(tt.fromOp, tt.e, tt.opts...)
			if tt.wantErrIs != nil {
				require.Error(err)
				assert.Nil(got)
				assert.ErrorIs(err, tt.wantErrIs)
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
		want            error
		wantErrIs       error
		wantErrContains string
	}{
		{
			name:            "missing-id",
			op:              Op("missing-id"),
			want:            fmt.Errorf("%s: missing id: %w", "missing-id", ErrInvalidParameter),
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing id",
		},
		{
			name:            "missing-operation",
			id:              "missing-operation",
			want:            fmt.Errorf("%s: missing operation: %w", "missing-operation", ErrInvalidParameter),
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing operation",
		},
		{
			name: "valid",
			op:   Op("valid"),
			id:   "valid",
			want: fmt.Errorf("%s: valid error: %w", "valid-error", ErrInvalidParameter),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			e := err{
				Op:    tt.op,
				Id:    Id(tt.id),
				Error: tt.want,
			}
			err := e.validate()
			if tt.wantErrIs != nil {
				require.Error(err)
				assert.ErrorIs(err, tt.wantErrIs)
				if tt.wantErrContains != "" {
					assert.Contains(err.Error(), tt.wantErrContains)
				}
				return
			}
			assert.NoError(err)
			assert.Equal(tt.want, e.Error)
		})
	}
}

func Test_errEventType(t *testing.T) {
	t.Parallel()
	e := &err{}
	assert.Equal(t, string(ErrorType), e.EventType())
}
