// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package sessions_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/hashicorp/boundary/sdk/pbs/controller/api"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/scopes"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/sessions"
	"github.com/hashicorp/boundary/sdk/wrapper"
	"github.com/hashicorp/eventlogger"
	"github.com/hashicorp/eventlogger/filters/encrypt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestSessions(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	pbNow := timestamppb.Now()
	wrapper := wrapper.TestWrapper(t)
	testEncryptingFilter := api.NewEncryptFilter(t, wrapper)
	testEncryptingFilter.FilterOperationOverrides = map[encrypt.DataClassification]encrypt.FilterOperation{
		// Use HMAC for sensitive fields for easy test comparisons
		encrypt.SensitiveClassification: encrypt.HmacSha256Operation,
	}

	tests := []struct {
		name string
		in   *eventlogger.Event
		want *eventlogger.Event
	}{
		{
			name: "session",
			in: &eventlogger.Event{
				Type:      "test",
				CreatedAt: now,
				Payload: &pb.Session{
					Id:       "id",
					TargetId: "target_id",
					Scope: &scopes.ScopeInfo{
						Id:            "scope-id",
						Type:          "scope-type",
						Name:          "scope-name",
						Description:   "scope-description",
						ParentScopeId: "scope-parent_scope_id",
					},
					CreatedTime:    pbNow,
					UpdatedTime:    pbNow,
					Version:        0,
					Type:           "type",
					ExpirationTime: pbNow,
					AuthTokenId:    "auth_token_id",
					UserId:         "user_id",
					HostSetId:      "host_set_id",
					HostId:         "host_id",
					ScopeId:        "scope_id",
					Endpoint:       "endpoint",
					States: []*pb.SessionState{
						{
							Status:    "status",
							StartTime: pbNow,
							EndTime:   pbNow,
						},
					},
					Status:            "status",
					Certificate:       []byte("certificate"),
					TerminationReason: "termination_reason",
					AuthorizedActions: []string{"action-1"},
					Connections: []*pb.Connection{
						{
							ClientTcpAddress:   "client_tcp_address",
							ClientTcpPort:      0,
							EndpointTcpAddress: "endpoint_tcp_address",
							EndpointTcpPort:    0,
							BytesUp:            0,
							BytesDown:          0,
							ClosedReason:       "closed_reason",
						},
					},
				},
			},
			want: &eventlogger.Event{
				Type:      "test",
				CreatedAt: now,
				Payload: &pb.Session{
					Id:       "id",
					TargetId: "target_id",
					Scope: &scopes.ScopeInfo{
						Id:            "scope-id",
						Type:          "scope-type",
						Name:          "scope-name",
						Description:   "scope-description",
						ParentScopeId: "scope-parent_scope_id",
					},
					CreatedTime:    pbNow,
					UpdatedTime:    pbNow,
					Version:        0,
					Type:           "type",
					ExpirationTime: pbNow,
					AuthTokenId:    "auth_token_id",
					UserId:         "user_id",
					HostSetId:      "host_set_id",
					HostId:         "host_id",
					ScopeId:        "scope_id",
					Endpoint:       "endpoint",
					States: []*pb.SessionState{
						{
							Status:    "status",
							StartTime: pbNow,
							EndTime:   pbNow,
						},
					},
					Status:            "status",
					Certificate:       []byte("certificate"),
					TerminationReason: "termination_reason",
					AuthorizedActions: []string{"action-1"},
					Connections: []*pb.Connection{
						{
							ClientTcpAddress:   "client_tcp_address",
							ClientTcpPort:      0,
							EndpointTcpAddress: "endpoint_tcp_address",
							EndpointTcpPort:    0,
							BytesUp:            0,
							BytesDown:          0,
							ClosedReason:       "closed_reason",
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := testEncryptingFilter.Process(ctx, tt.in)
			require.NoError(err)
			require.NotNil(got)
			gotJSON, err := json.Marshal(got)
			require.NoError(err)

			wantJSON, err := json.Marshal(tt.want)
			require.NoError(err)
			assert.JSONEq(string(wantJSON), string(gotJSON))
		})
	}
}
