// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package targets_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/scopes"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/targets"
	"github.com/hashicorp/boundary/sdk/wrapper"
	"github.com/hashicorp/eventlogger"
	"github.com/hashicorp/eventlogger/filters/encrypt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func TestTargets(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	pbNow := timestamppb.Now()
	wrapper := wrapper.TestWrapper(t)
	testEncryptingFilter := api.NewEncryptFilter(t, wrapper)

	tests := []struct {
		name string
		in   *eventlogger.Event
		want *eventlogger.Event
	}{
		{
			name: "target",
			in: &eventlogger.Event{
				Type:      "test",
				CreatedAt: now,
				Payload: &pb.Target{
					Id:      "id",
					ScopeId: "scope-id",
					Scope: &scopes.ScopeInfo{
						Id:            "id",
						Type:          "type",
						Name:          "name",
						Description:   "description",
						ParentScopeId: "parent-scope-id",
					},
					Name:        &wrapperspb.StringValue{Value: "name"},
					Description: &wrapperspb.StringValue{Value: "description"},
					CreatedTime: pbNow,
					UpdatedTime: pbNow,
					Version:     0,
					Type:        "type",
					HostSourceIds: []string{
						"host-source-id",
					},
					HostSources: []*pb.HostSource{
						{
							Id:            "id",
							HostCatalogId: "host-catalog-id",
						},
					},
					SessionMaxSeconds:           &wrapperspb.UInt32Value{Value: 0},
					SessionConnectionLimit:      &wrapperspb.Int32Value{Value: 0},
					EgressWorkerFilter:          &wrapperspb.StringValue{Value: "egress-worker-filter"},
					BrokeredCredentialSourceIds: []string{"brokered-credential-source-id"},
					BrokeredCredentialSources: []*pb.CredentialSource{
						{
							Id:                "id",
							Name:              "name",
							Description:       "description",
							CredentialStoreId: "credential-store-id",
							Type:              "type",
							CredentialType:    "credential-type",
						},
					},
					InjectedApplicationCredentialSourceIds: []string{"injected-app-credential-source-id"},
					InjectedApplicationCredentialSources: []*pb.CredentialSource{
						{
							Id:                "id",
							Name:              "name",
							Description:       "description",
							CredentialStoreId: "credential-store-id",
							Type:              "type",
							CredentialType:    "credential-type",
						},
					},
					Attrs: &pb.Target_TcpTargetAttributes{
						TcpTargetAttributes: &pb.TcpTargetAttributes{
							DefaultPort:       &wrapperspb.UInt32Value{Value: 26},
							DefaultClientPort: &wrapperspb.UInt32Value{Value: 27},
						},
					},
					AuthorizedActions: []string{"action-1"},
				},
			},
			want: &eventlogger.Event{
				Type:      "test",
				CreatedAt: now,
				Payload: &pb.Target{
					Id:      "id",
					ScopeId: "scope-id",
					Scope: &scopes.ScopeInfo{
						Id:            "id",
						Type:          "type",
						Name:          "name",
						Description:   "description",
						ParentScopeId: "parent-scope-id",
					},
					Name:        &wrapperspb.StringValue{Value: "name"},
					Description: &wrapperspb.StringValue{Value: "description"},
					CreatedTime: pbNow,
					UpdatedTime: pbNow,
					Version:     0,
					Type:        "type",
					HostSourceIds: []string{
						"host-source-id",
					},
					HostSources: []*pb.HostSource{
						{
							Id:            "id",
							HostCatalogId: "host-catalog-id",
						},
					},
					SessionMaxSeconds:           &wrapperspb.UInt32Value{Value: 0},
					SessionConnectionLimit:      &wrapperspb.Int32Value{Value: 0},
					EgressWorkerFilter:          &wrapperspb.StringValue{Value: "egress-worker-filter"},
					BrokeredCredentialSourceIds: []string{"brokered-credential-source-id"},
					BrokeredCredentialSources: []*pb.CredentialSource{
						{
							Id:                "id",
							Name:              "name",
							Description:       "description",
							CredentialStoreId: "credential-store-id",
							Type:              "type",
							CredentialType:    "credential-type",
						},
					},
					InjectedApplicationCredentialSourceIds: []string{"injected-app-credential-source-id"},
					InjectedApplicationCredentialSources: []*pb.CredentialSource{
						{
							Id:                "id",
							Name:              "name",
							Description:       "description",
							CredentialStoreId: "credential-store-id",
							Type:              "type",
							CredentialType:    "credential-type",
						},
					},
					Attrs: &pb.Target_TcpTargetAttributes{
						TcpTargetAttributes: &pb.TcpTargetAttributes{
							DefaultPort:       &wrapperspb.UInt32Value{Value: 26},
							DefaultClientPort: &wrapperspb.UInt32Value{Value: 27},
						},
					},
					AuthorizedActions: []string{"action-1"},
				},
			},
		},
		{
			name: "authorize-session-request",
			in: &eventlogger.Event{
				Type:      "test",
				CreatedAt: now,
				Payload: &pbs.AuthorizeSessionRequest{
					Id:        "id",
					Name:      "name",
					ScopeId:   "scope-id",
					ScopeName: "scope-name",
					HostId:    "host-id",
				},
			},
			want: &eventlogger.Event{
				Type:      "test",
				CreatedAt: now,
				Payload: &pbs.AuthorizeSessionRequest{
					Id:        "id",
					Name:      "name",
					ScopeId:   "scope-id",
					ScopeName: "scope-name",
					HostId:    "host-id",
				},
			},
		},
		{
			name: "authorize-session-response",
			in: &eventlogger.Event{
				Type:      "test",
				CreatedAt: now,
				Payload: &pbs.AuthorizeSessionResponse{
					Item: &pb.SessionAuthorization{
						SessionId: "session-id",
						TargetId:  "target-id",
						Scope: &scopes.ScopeInfo{
							Id:            "id",
							Type:          "type",
							Name:          "name",
							Description:   "description",
							ParentScopeId: "parent-scope-id",
						},
						CreatedTime:        pbNow,
						UserId:             "user-id",
						HostSetId:          "host-set-id",
						HostId:             "host-id",
						Type:               "type",
						AuthorizationToken: "authorization-token",
						Endpoint:           "endpoint",
						Credentials: []*pb.SessionCredential{
							{
								CredentialSource: &pb.CredentialSource{
									Id:                "id",
									Name:              "name",
									Description:       "description",
									CredentialStoreId: "credential-store-id",
									Type:              "type",
									CredentialType:    "credential-type",
								},
								Secret: &pb.SessionSecret{
									Raw: "raw-secrets",
									Decoded: &structpb.Struct{
										Fields: map[string]*structpb.Value{
											"key1": structpb.NewStringValue("value-1"),
										},
									},
								},
								Credential: &structpb.Struct{
									Fields: map[string]*structpb.Value{
										"key1": structpb.NewStringValue("value-1"),
									},
								},
							},
						},
					},
				},
			},
			want: &eventlogger.Event{
				Type:      "test",
				CreatedAt: now,
				Payload: &pbs.AuthorizeSessionResponse{
					Item: &pb.SessionAuthorization{
						SessionId: "session-id",
						TargetId:  "target-id",
						Scope: &scopes.ScopeInfo{
							Id:            "id",
							Type:          "type",
							Name:          "name",
							Description:   "description",
							ParentScopeId: "parent-scope-id",
						},
						CreatedTime:        pbNow,
						UserId:             "user-id",
						HostSetId:          "host-set-id",
						HostId:             "host-id",
						Type:               "type",
						AuthorizationToken: encrypt.RedactedData,
						Endpoint:           "endpoint",
						Credentials: []*pb.SessionCredential{
							{
								CredentialSource: &pb.CredentialSource{
									Id:                "id",
									Name:              "name",
									Description:       "description",
									CredentialStoreId: "credential-store-id",
									Type:              "type",
									CredentialType:    "credential-type",
								},
								Secret: &pb.SessionSecret{
									Raw: encrypt.RedactedData,
									Decoded: &structpb.Struct{
										Fields: map[string]*structpb.Value{
											"key1": structpb.NewStringValue(encrypt.RedactedData),
										},
									},
								},
								Credential: &structpb.Struct{
									Fields: map[string]*structpb.Value{
										"key1": structpb.NewStringValue(encrypt.RedactedData),
									},
								},
							},
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
