// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package event

import (
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/scopes"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/workers"
	"github.com/hashicorp/eventlogger"
	"github.com/hashicorp/eventlogger/filters/gated"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"
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
		wantDetailsPaylaod   []gated.EventPayloadDetails
	}{
		{
			name:   "authenticate-op",
			fromOp: Op("ldap.Authenticate"),
			opts: []Option{
				WithId("authenticate-op"),
				WithRequestInfo(TestRequestInfo(t)),
				WithNow(now),
				WithDetails(
					"user_id", "u_1234567890",
					"auth_toke_start", "12345789",
					"auth_toke_end", "12345789"),
			},
			wantObservation: &observation{
				ID:          "authenticate-op",
				Version:     errorVersion,
				Op:          Op("ldap.Authenticate"),
				RequestInfo: TestRequestInfo(t),
				Detail: map[string]any{
					"user_id":         "u_1234567890",
					"auth_toke_start": "12345789",
					"auth_toke_end":   "12345789",
				},
			},
			wantDetailsPaylaod: []gated.EventPayloadDetails{
				{
					CreatedAt: now.String(),
					Type:      "ldap.Authenticate",
					Payload: map[string]interface{}{
						"user_id":         "u_1234567890",
						"auth_toke_start": "12345789",
						"auth_toke_end":   "12345789",
					},
				},
			},
		},
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
		{
			name:   "workers-list-details-with-telemetry",
			fromOp: Op("workers-list-details-with-telemetry"),
			opts: []Option{
				WithId("workers-list-details-with-telemetry"),
				WithRequestInfo(TestRequestInfo(t)),
				WithFlush(),
				WithRequest(&Request{
					Details: &services.ListWorkersRequest{
						ScopeId:   "global",
						Recursive: false,
						Filter:    "",
					},
				}),
				WithResponse(&Response{
					StatusCode: 200,
					Details: &services.ListWorkersResponse{
						Items: []*workers.Worker{
							{
								Id:      "w_V7vkJAMxat",
								ScopeId: "global",
								Scope: &scopes.ScopeInfo{
									Id:          "global",
									Type:        "global",
									Name:        "global",
									Description: "Global Scope",
								},
								Name:        &wrapperspb.StringValue{Value: "[REDACTED]"},
								Description: &wrapperspb.StringValue{Value: "[REDACTED]"},
								CreatedTime: &timestamppb.Timestamp{
									Seconds: 1694589179,
									Nanos:   812910000,
								},
								UpdatedTime: &timestamppb.Timestamp{
									Seconds: 1694589211,
									Nanos:   371831000,
								},
								Version: 1,
								Address: "127.0.0.1:9202",
								LastStatusTime: &timestamppb.Timestamp{
									Seconds: 1694589211,
									Nanos:   371831000,
								},
								ActiveConnectionCount:              nil,
								Type:                               "[REDACTED]",
								ReleaseVersion:                     "Boundary v0.13.2",
								DirectlyConnectedDownstreamWorkers: []string{"test1", "test2"},
								AuthorizedActions:                  []string{"read", "delete"},
							},
						},
					},
				}),
				WithTelemetry(),
			},
			wantObservation: &observation{
				ID:          "workers-list-details-with-telemetry",
				Flush:       true,
				Version:     errorVersion,
				Op:          Op("workers-list-details-with-telemetry"),
				RequestInfo: TestRequestInfo(t),
				Request: &Request{
					Details: &services.ListWorkersRequest{
						ScopeId:   "global",
						Recursive: false,
						Filter:    "",
					},
				},
				Response: &Response{
					StatusCode: 200,
					Details: &services.ListWorkersResponse{
						Items: []*workers.Worker{
							{
								Id:      "w_V7vkJAMxat",
								ScopeId: "global",
								Scope: &scopes.ScopeInfo{
									Id:          "global",
									Type:        "global",
									Name:        "global",
									Description: "Global Scope",
								},
								Name:        &wrapperspb.StringValue{Value: "[REDACTED]"},
								Description: &wrapperspb.StringValue{Value: "[REDACTED]"},
								CreatedTime: &timestamppb.Timestamp{
									Seconds: 1694589179,
									Nanos:   812910000,
								},
								UpdatedTime: &timestamppb.Timestamp{
									Seconds: 1694589211,
									Nanos:   371831000,
								},
								Version: 1,
								Address: "127.0.0.1:9202",
								LastStatusTime: &timestamppb.Timestamp{
									Seconds: 1694589211,
									Nanos:   371831000,
								},
								ActiveConnectionCount:              nil,
								Type:                               "[REDACTED]",
								ReleaseVersion:                     "Boundary v0.13.2",
								DirectlyConnectedDownstreamWorkers: []string{"test1", "test2"},
								AuthorizedActions:                  []string{"read", "delete"},
							},
						},
					},
				},
			},
			wantFilteredRequest: &Request{
				Details: &services.ListWorkersRequest{
					ScopeId: "global",
				},
			},
			wantFilteredResponse: &Response{
				StatusCode: 200,
				Details: &services.ListWorkersResponse{
					Items: []*workers.Worker{
						{
							Id:      "w_V7vkJAMxat",
							ScopeId: "global",
							Scope: &scopes.ScopeInfo{
								Id:   "global",
								Type: "global",
							},
							CreatedTime: &timestamppb.Timestamp{
								Seconds: 1694589179,
								Nanos:   812910000,
							},
							UpdatedTime: &timestamppb.Timestamp{
								Seconds: 1694589211,
								Nanos:   371831000,
							},
							LastStatusTime: &timestamppb.Timestamp{
								Seconds: 1694589211,
								Nanos:   371831000,
							},
							DirectlyConnectedDownstreamWorkers: []string{"test1", "test2"},
							ReleaseVersion:                     "Boundary v0.13.2",
						},
					},
				},
			},
		},
		{
			name:   "with-request-client-headers-with-telemetry",
			fromOp: Op("with-request-client-headers-with-telemetry"),
			opts: []Option{
				WithId("with-request-client-headers-with-telemetry"),
				WithRequestInfo(TestRequestInfo(t)),
				WithFlush(),
				WithRequest(&Request{
					Operation: "op",
					Endpoint:  "/auth-tokens/<id>",
					Details:   testWorkerStatus(t),
					UserAgents: []*UserAgent{{
						Product:        "Boundary-client-agent",
						ProductVersion: "0.1.4",
					}},
				}),
				WithTelemetry(),
			},
			wantObservation: &observation{
				ID:          "with-request-client-headers-with-telemetry",
				Flush:       true,
				Version:     errorVersion,
				Op:          Op("with-request-client-headers-with-telemetry"),
				RequestInfo: TestRequestInfo(t),
				Request: &Request{
					Operation: "op",
					Endpoint:  "/auth-tokens/<id>",
					Details:   testWorkerStatus(t),
					UserAgents: []*UserAgent{{
						Product:        "Boundary-client-agent",
						ProductVersion: "0.1.4",
					}},
				},
			},
			wantFilteredRequest: &Request{
				Operation: "op",
				Endpoint:  "/auth-tokens/<id>",
				Details:   testWorkerStatusObservable(t),
				UserAgents: []*UserAgent{{
					Product:        "Boundary-client-agent",
					ProductVersion: "0.1.4",
				}},
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
				assert.True(proto.Equal(tt.wantFilteredResponse.Details, pmsg.Details), "protos differ:\nexpected: %+v\nactual: %+v", tt.wantFilteredResponse.Details, pmsg.Details)
			}
			if tt.wantDetailsPaylaod != nil {
				details, ok := payload["details"]
				assert.True(ok)
				assert.NotNil(details)
				detailsPayload, ok := details.([]gated.EventPayloadDetails)
				assert.True(ok)
				assert.NotNil(detailsPayload)
				assert.Equal(tt.wantDetailsPaylaod, detailsPayload)
			}
		})
	}
}
