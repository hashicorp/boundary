// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package event

import (
	"testing"
	"time"

	"github.com/hashicorp/eventlogger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
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

func Test_composeFromTelemetryFiltering(t *testing.T) {
	t.Parallel()

	now := time.Now()

	tests := []struct {
		name                 string
		fromOp               Op
		opts                 []Option
		wantObservation      *observation
		wantErrIs            error
		wantErrContains      string
		wantFilteredRequest  *Request
		wantFilteredResponse *Response
	}{
		{
			name:   "with-request-no-telemetry",
			fromOp: Op("with-request-no-telemetry"),
			opts: []Option{
				WithId("with-request-no-telemetry"),
				WithRequestInfo(TestRequestInfo(t)),
				WithFlush(),
				WithRequest(&Request{
					Operation: "op",
					Endpoint:  "/worker-status/<id>",
					Details:   testWorkerStatus(t),
				}),
			},
			wantObservation: &observation{
				ID:          "with-request-no-telemetry",
				Flush:       true,
				Version:     errorVersion,
				Op:          Op("with-request-no-telemetry"),
				RequestInfo: TestRequestInfo(t),
			},
		},
		{
			name:   "with-response-no-telemetry",
			fromOp: Op("with-response-no-telemetry"),
			opts: []Option{
				WithId("with-response-no-telemetry"),
				WithRequestInfo(TestRequestInfo(t)),
				WithFlush(),
				WithResponse(&Response{
					StatusCode: 200,
					Details:    testWorkerStatus(t),
				}),
			},
			wantObservation: &observation{
				ID:          "with-response-no-telemetry",
				Flush:       true,
				Version:     errorVersion,
				Op:          Op("with-response-no-telemetry"),
				RequestInfo: TestRequestInfo(t),
			},
		},
		{
			name:   "with-request-with-telemetry",
			fromOp: Op("with-request-with-telemetry"),
			opts: []Option{
				WithId("with-request-with-telemetry"),
				WithRequestInfo(TestRequestInfo(t)),
				WithFlush(),
				WithRequest(&Request{
					Operation: "op",
					Endpoint:  "/worker-status/<id>",
					Details:   testWorkerStatus(t),
				}),
				WithTelemetry(),
			},
			wantObservation: &observation{
				ID:          "with-request-with-telemetry",
				Flush:       true,
				Version:     errorVersion,
				Op:          Op("with-request-with-telemetry"),
				RequestInfo: TestRequestInfo(t),
				Request: &Request{
					Operation: "op",
					Endpoint:  "/worker-status/<id>",
					Details:   testWorkerStatus(t),
				},
			},
			wantFilteredRequest: &Request{
				Operation: "op",
				Endpoint:  "/worker-status/<id>",
				Details:   testWorkerStatusObservable(t),
			},
		},
		{
			name:   "with-response-with-telemetry",
			fromOp: Op("with-response-with-telemetry"),
			opts: []Option{
				WithId("with-response-with-telemetry"),
				WithRequestInfo(TestRequestInfo(t)),
				WithFlush(),
				WithResponse(&Response{
					StatusCode: 200,
					Details:    testWorkerStatus(t),
				}),
				WithTelemetry(),
			},
			wantObservation: &observation{
				ID:          "with-response-with-telemetry",
				Flush:       true,
				Version:     errorVersion,
				Op:          Op("with-response-with-telemetry"),
				RequestInfo: TestRequestInfo(t),
				Response: &Response{
					StatusCode: 200,
					Details:    testWorkerStatus(t),
				},
			},
			wantFilteredResponse: &Response{
				StatusCode: 200,
				Details:    testWorkerStatusObservable(t),
			},
		},
		{
			name:   "nil-request-details-with-telemetry",
			fromOp: Op("nil-request-details-with-telemetry"),
			opts: []Option{
				WithId("nil-request-details-with-telemetry"),
				WithRequestInfo(TestRequestInfo(t)),
				WithFlush(),
				WithRequest(&Request{
					Operation: "op",
					Endpoint:  "/worker-status/<id>",
					Details:   nil,
				}),
				WithTelemetry(),
			},
			wantObservation: &observation{
				ID:          "nil-request-details-with-telemetry",
				Flush:       true,
				Version:     errorVersion,
				Op:          Op("nil-request-details-with-telemetry"),
				RequestInfo: TestRequestInfo(t),
				Request: &Request{
					Operation: "op",
					Endpoint:  "/worker-status/<id>",
					Details:   nil,
				},
			},
			wantFilteredRequest: &Request{
				Operation: "op",
				Endpoint:  "/worker-status/<id>",
				Details:   nil,
			},
		},
		{
			name:   "nil-response-details-with-telemetry",
			fromOp: Op("nil-response-details-with-telemetry"),
			opts: []Option{
				WithId("nil-response-details-with-telemetry"),
				WithRequestInfo(TestRequestInfo(t)),
				WithFlush(),
				WithResponse(&Response{
					StatusCode: 200,
					Details:    nil,
				}),
				WithTelemetry(),
			},
			wantObservation: &observation{
				ID:          "nil-response-details-with-telemetry",
				Flush:       true,
				Version:     errorVersion,
				Op:          Op("nil-response-details-with-telemetry"),
				RequestInfo: TestRequestInfo(t),
				Response: &Response{
					StatusCode: 200,
					Details:    nil,
				},
			},
			wantFilteredResponse: &Response{
				StatusCode: 200,
				Details:    nil,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := newObservation(tt.fromOp, tt.opts...)
			require.NoError(err)
			require.NotNil(got)
			opts := getOpts(tt.opts...)
			if opts.withId == "" {
				tt.wantObservation.ID = got.ID
			}
			assert.Equal(tt.wantObservation, got)
			// feed the event through ComposeFrom which will filter any request/response data
			_, ev, err := got.ComposeFrom(
				[]*eventlogger.Event{
					{
						Type:      "observation",
						CreatedAt: now,
						Payload:   got,
					},
				},
			)
			if tt.wantErrIs != nil {
				require.Error(err)
				assert.Nil(got)
				assert.ErrorIs(err, tt.wantErrIs)
				if tt.wantErrContains != "" {
					assert.Contains(err.Error(), tt.wantErrContains)
				}
				return
			}
			payload, ok := ev.(map[string]any)
			assert.True(ok)
			assert.NotNil(payload)
			if tt.wantFilteredRequest != nil {
				req, ok := payload["request"]
				assert.True(ok)
				assert.NotNil(req)
				pmsg, ok := req.(*Request)
				assert.True(ok)
				assert.NotNil(pmsg)
				assert.True(proto.Equal(tt.wantFilteredRequest.Details, pmsg.Details))
			}
			if tt.wantFilteredResponse != nil {
				req, ok := payload["response"]
				assert.True(ok)
				assert.NotNil(req)
				pmsg, ok := req.(*Response)
				assert.True(ok)
				assert.NotNil(pmsg)
				assert.True(proto.Equal(tt.wantFilteredResponse.Details, pmsg.Details))
			}
		})
	}
}
