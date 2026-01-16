// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package event

import (
	"fmt"
	"testing"

	"github.com/hashicorp/go-multierror"
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
				ErrorFields: fmt.Errorf("%s: valid no opts: %w", "valid-no-opts", ErrInvalidParameter),
				Error:       "valid-no-opts: valid no opts: invalid parameter",
				Version:     errorVersion,
				Op:          Op("valid-no-opts"),
			},
		},
		{
			name:   "valid-all-opts",
			fromOp: Op("valid-all-opts"),
			e:      fmt.Errorf("%s: valid all opts: %w", "valid-all-opts", ErrInvalidParameter),
			opts: []Option{
				WithId("valid-all-opts"),
				WithRequestInfo(TestRequestInfo(t)),
				WithInfo("msg", "hello"),
			},
			want: &err{
				ErrorFields: fmt.Errorf("%s: valid all opts: %w", "valid-all-opts", ErrInvalidParameter),
				Error:       "valid-all-opts: valid all opts: invalid parameter",
				Version:     errorVersion,
				Op:          Op("valid-all-opts"),
				Id:          "valid-all-opts",
				RequestInfo: TestRequestInfo(t),
				Info:        map[string]any{"msg": "hello"},
			},
		},
		{
			name:   "multierror-conversion",
			fromOp: Op("multierror"),
			e: func() error {
				return multierror.Append(fmt.Errorf("%s: multierror all opts: %w", "multierror", ErrInvalidParameter))
			}(),
			opts: []Option{
				WithId("multierror"),
				WithRequestInfo(TestRequestInfo(t)),
				WithInfo("msg", "hello"),
			},
			want: &err{
				ErrorFields: fmt.Errorf("1 error occurred:\n\t* multierror: multierror all opts: invalid parameter\n\n"),
				Error:       "1 error occurred:\n\t* multierror: multierror all opts: invalid parameter\n\n",
				Version:     errorVersion,
				Op:          Op("multierror"),
				Id:          "multierror",
				RequestInfo: TestRequestInfo(t),
				Info:        map[string]any{"msg": "hello"},
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
		wantError       string
		wantFields      error
		wantErrIs       error
		wantErrContains string
	}{
		{
			name:            "missing-id",
			op:              Op("missing-id"),
			wantFields:      fmt.Errorf("%s: missing id: %w", "missing-id", ErrInvalidParameter),
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing id",
		},
		{
			name:            "missing-operation",
			id:              "missing-operation",
			wantFields:      fmt.Errorf("%s: missing operation: %w", "missing-operation", ErrInvalidParameter),
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing operation",
		},
		{
			name:            "missing-error",
			op:              Op("missing-error"),
			id:              "missing-error",
			wantFields:      fmt.Errorf("%s: missing operation: %w", "missing-operation", ErrInvalidParameter),
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing error",
		},
		{
			name:            "missing-error-fields",
			op:              Op("missing-error-fields"),
			id:              "missing-error-fields",
			wantError:       "test error",
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing error",
		},
		{
			name:       "valid",
			op:         Op("valid"),
			id:         "valid",
			wantFields: fmt.Errorf("%s: valid error: %w", "valid-error", ErrInvalidParameter),
			wantError:  "test error",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			e := err{
				Op:          tt.op,
				Id:          Id(tt.id),
				ErrorFields: tt.wantFields,
				Error:       tt.wantError,
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
			assert.Equal(tt.wantFields, e.ErrorFields)
			assert.Equal(tt.wantError, e.Error)
		})
	}
}

func Test_errEventType(t *testing.T) {
	t.Parallel()
	e := &err{}
	assert.Equal(t, string(ErrorType), e.EventType())
}
