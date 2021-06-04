package event

import (
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/eventlogger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_newObservation(t *testing.T) {
	t.Parallel()

	now := time.Now()

	testHeader := map[string]interface{}{
		"public-id": "public-id",
		"now":       now,
	}

	testDetails := map[string]interface{}{
		"file_name": "tmpfile-name",
	}

	tests := []struct {
		name            string
		fromOp          Op
		opts            []Option
		want            *observation
		wantErrMatch    *errors.Template
		wantErrContains string
	}{
		{
			name:            "missing-op",
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing operation",
		},
		{
			name:   "valid-no-opts",
			fromOp: Op("valid-no-opts"),
			want: &observation{
				SimpleGatedPayload: &eventlogger.SimpleGatedPayload{},
				Version:            ErrorVersion,
				Op:                 Op("valid-no-opts"),
			},
		},
		{
			name:   "valid-all-opts",
			fromOp: Op("valid-all-opts"),
			opts: []Option{
				WithId("valid-all-opts"),
				WithRequestInfo(TestRequestInfo(t)),
				WithHeader(testHeader),
				WithDetails(testDetails),
				WithFlush(),
			},
			want: &observation{
				SimpleGatedPayload: &eventlogger.SimpleGatedPayload{
					ID:     "valid-all-opts",
					Header: testHeader,
					Detail: testDetails,
					Flush:  true,
				},
				Version:     ErrorVersion,
				Op:          Op("valid-all-opts"),
				RequestInfo: TestRequestInfo(t),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := newObservation(tt.fromOp, tt.opts...)
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
		wantErrMatch    *errors.Template
		wantErrContains string
	}{
		{
			name:            "missing-id",
			op:              Op("missing-id"),
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing id",
		},
		{
			name:            "missing-operation",
			id:              "missing-operation",
			wantErrMatch:    errors.T(errors.InvalidParameter),
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
				SimpleGatedPayload: &eventlogger.SimpleGatedPayload{
					ID: tt.id,
				},
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
		})
	}
}

func Test_observationEventType(t *testing.T) {
	t.Parallel()
	e := &observation{}
	assert.Equal(t, string(ObservationType), e.EventType())
}
