// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package event

import (
	"bytes"
	"encoding/json"
	"errors"
	stderrors "errors"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
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
				Error:   "valid-no-opts: valid no opts: invalid parameter",
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
				WithInfo("msg", "hello"),
			},
			want: &err{
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
				Error:       "1 error occurred:\n\t* multierror: multierror all opts: invalid parameter\n\n",
				Version:     errorVersion,
				Op:          Op("multierror"),
				Id:          "multierror",
				RequestInfo: TestRequestInfo(t),
				Info:        map[string]any{"msg": "hello"},
			},
		},
		{
			name:   "multierror-conversion-from-errors.Join",
			fromOp: Op("test"),
			e: func() error {
				return errors.Join(multierror.Append(fmt.Errorf("%s: multierror all opts: %w", "multierror", ErrInvalidParameter)))
			}(),
			opts: []Option{
				WithId("1"),
				WithRequestInfo(TestRequestInfo(t)),
				WithInfo("msg", "hello"),
			},
			want: &err{
				Error:       "1 error occurred:\n\t* multierror: multierror all opts: invalid parameter\n\n",
				Version:     errorVersion,
				Op:          Op("test"),
				Id:          "1",
				RequestInfo: TestRequestInfo(t),
				Info:        map[string]any{"msg": "hello"},
			},
		},
		{
			name:   "multierror.Group",
			fromOp: Op("test"),
			e: func() error {
				var mg multierror.Group
				mg.Go(func() error {
					return multierror.Append(errors.New("error"))
				})

				stopErrors := mg.Wait()
				return stderrors.Join(stopErrors)
			}(),
			opts: []Option{
				WithId("1"),
				WithRequestInfo(TestRequestInfo(t)),
				WithInfo("msg", "hello"),
			},
			want: &err{
				Error:       "1 error occurred:\n\t* error\n\n",
				Version:     errorVersion,
				Op:          Op("test"),
				Id:          "1",
				RequestInfo: TestRequestInfo(t),
				Info:        map[string]any{"msg": "hello"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, gotErr := newError(tt.fromOp, tt.e, tt.opts...)
			if tt.wantErrIs != nil {
				require.Error(gotErr)
				assert.Nil(got)
				assert.ErrorIs(gotErr, tt.wantErrIs)
				if tt.wantErrContains != "" {
					assert.Contains(gotErr.Error(), tt.wantErrContains)
				}
				return
			}
			require.NoError(gotErr)
			require.NotNil(got)
			opts := getOpts(tt.opts...)
			if opts.withId == "" {
				tt.want.Id = got.Id
			}
			if opts.withRequestInfo != nil {
				tt.want.RequestInfo = got.RequestInfo
			}
			require.NotEmpty(got.ErrorFields)
			// make sure it can be encoded
			buf := &bytes.Buffer{}
			enc := json.NewEncoder(buf)
			gotErr = enc.Encode(got)
			assert.NoError(gotErr)
			t.Log(buf.String())

			buf.Reset()
			enc.SetIndent("", "  ")
			gotErr = enc.Encode(got)
			assert.NoError(gotErr)
			t.Log(buf.String())

			assert.Empty(cmp.Diff(tt.want, got, cmpopts.IgnoreFields(err{}, "ErrorFields")))
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
