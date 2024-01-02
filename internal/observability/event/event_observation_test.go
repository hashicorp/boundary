// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1


package event

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_newObservation(t *testing.T) {
	t.Parallel()

	now := time.Now()

	testHeader := []any{"public-id", "public-id", "now", now}

	testDetails := []any{"file_name", "tmpfile-name"}

	tests := []struct {
		name            string
		fromOp          Op
		opts            []Option
		want            *observation
		wantErrIs       error
		wantErrContains string
	}{
		{
			name:            "missing-op",
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing operation",
		},
		{
			name:   "valid-no-opts",
			fromOp: Op("valid-no-opts"),
			want: &observation{
				Version: errorVersion,
				Op:      Op("valid-no-opts"),
			},
		},
		{
			name:   "valid-all-opts",
			fromOp: Op("valid-all-opts"),
			opts: []Option{
				WithId("valid-all-opts"),
				WithRequestInfo(TestRequestInfo(t)),
				WithHeader(testHeader...),
				WithDetails(testDetails...),
				WithFlush(),
			},
			want: &observation{
				ID:          "valid-all-opts",
				Header:      map[string]any{"public-id": "public-id", "now": now},
				Detail:      map[string]any{"file_name": "tmpfile-name"},
				Flush:       true,
				Version:     errorVersion,
				Op:          Op("valid-all-opts"),
				RequestInfo: TestRequestInfo(t),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := newObservation(tt.fromOp, tt.opts...)
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
				tt.want.ID = got.ID
			}
			assert.Equal(tt.want, got)
		})
	}
}

func Test_observationvalidate(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name            string
		id              string
		op              Op
		wantErrIs       error
		wantErrContains string
	}{
		{
			name:            "missing-id",
			op:              Op("missing-id"),
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing id",
		},
		{
			name:            "missing-operation",
			id:              "missing-operation",
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing operation",
		},
		{
			name: "valid",
			op:   Op("valid"),
			id:   "valid",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			e := observation{
				Op: tt.op,
				ID: tt.id,
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
		})
	}
}

func Test_observationEventType(t *testing.T) {
	t.Parallel()
	e := &observation{}
	assert.Equal(t, string(ObservationType), e.EventType())
}
