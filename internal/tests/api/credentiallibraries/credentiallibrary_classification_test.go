// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package credentiallibraries_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/hashicorp/boundary/sdk/pbs/controller/api"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/credentiallibraries"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/scopes"
	"github.com/hashicorp/boundary/sdk/wrapper"
	"github.com/hashicorp/eventlogger"
	"github.com/hashicorp/eventlogger/filters/encrypt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func TestCredentialLibraryClassification(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	pbNow := timestamppb.Now()
	wrapper := wrapper.TestWrapper(t)
	testEncryptingFilter := api.NewEncryptFilter(t, wrapper)

	cases := []struct {
		name string
		in   *eventlogger.Event
		want *eventlogger.Event
	}{
		{
			"Vault",
			&eventlogger.Event{
				Type:      "test",
				CreatedAt: now,
				Payload: &pb.CredentialLibrary{
					Id:                "id",
					CredentialStoreId: "credential-store-id",
					Scope: &scopes.ScopeInfo{
						Id:            "scope-id",
						Type:          "scope-type",
						Name:          "scope-name",
						Description:   "scope-descriptione",
						ParentScopeId: "scope-parent-scope-id",
					},
					Name:        &wrapperspb.StringValue{Value: "name"},
					Description: &wrapperspb.StringValue{Value: "description"},
					CreatedTime: pbNow,
					UpdatedTime: pbNow,
					Version:     1,
					Type:        "vault",
					Attrs: &pb.CredentialLibrary_VaultCredentialLibraryAttributes{
						VaultCredentialLibraryAttributes: &pb.VaultCredentialLibraryAttributes{
							Path:            &wrapperspb.StringValue{Value: "/path"},
							HttpMethod:      &wrapperspb.StringValue{Value: "POST"},
							HttpRequestBody: &wrapperspb.StringValue{Value: `{"request": "body-secret"}`},
						},
					},
					AuthorizedActions: []string{"action-1", "action-2"},
					CredentialType:    "credential-type",
					CredentialMappingOverrides: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"override-1": structpb.NewStringValue("one"),
							"override-2": structpb.NewStringValue("two"),
						},
					},
				},
			},
			&eventlogger.Event{
				Type:      "test",
				CreatedAt: now,
				Payload: &pb.CredentialLibrary{
					Id:                "id",
					CredentialStoreId: "credential-store-id",
					Scope: &scopes.ScopeInfo{
						Id:            "scope-id",
						Type:          "scope-type",
						Name:          "scope-name",
						Description:   "scope-descriptione",
						ParentScopeId: "scope-parent-scope-id",
					},
					Name:        &wrapperspb.StringValue{Value: "name"},
					Description: &wrapperspb.StringValue{Value: "description"},
					CreatedTime: pbNow,
					UpdatedTime: pbNow,
					Version:     1,
					Type:        "vault",
					Attrs: &pb.CredentialLibrary_VaultCredentialLibraryAttributes{
						VaultCredentialLibraryAttributes: &pb.VaultCredentialLibraryAttributes{
							Path:            &wrapperspb.StringValue{Value: "/path"},
							HttpMethod:      &wrapperspb.StringValue{Value: "POST"},
							HttpRequestBody: &wrapperspb.StringValue{Value: encrypt.RedactedData},
						},
					},
					AuthorizedActions: []string{"action-1", "action-2"},
					CredentialType:    "credential-type",
					CredentialMappingOverrides: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"override-1": structpb.NewStringValue(encrypt.RedactedData),
							"override-2": structpb.NewStringValue(encrypt.RedactedData),
						},
					},
				},
			},
		},
		{
			"Default",
			&eventlogger.Event{
				Type:      "test",
				CreatedAt: now,
				Payload: &pb.CredentialLibrary{
					Id:                "id",
					CredentialStoreId: "credential-store-id",
					Scope: &scopes.ScopeInfo{
						Id:            "scope-id",
						Type:          "scope-type",
						Name:          "scope-name",
						Description:   "scope-descriptione",
						ParentScopeId: "scope-parent-scope-id",
					},
					Name:        &wrapperspb.StringValue{Value: "name"},
					Description: &wrapperspb.StringValue{Value: "description"},
					CreatedTime: pbNow,
					UpdatedTime: pbNow,
					Version:     1,
					Type:        "default",
					Attrs: &pb.CredentialLibrary_Attributes{
						Attributes: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								"field1": structpb.NewStringValue("vaule1"),
								"field2": structpb.NewStringValue("vaule2"),
							},
						},
					},
					AuthorizedActions: []string{"action-1", "action-2"},
					CredentialType:    "credential-type",
					CredentialMappingOverrides: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"override-1": structpb.NewStringValue("one"),
							"override-2": structpb.NewStringValue("two"),
						},
					},
				},
			},
			&eventlogger.Event{
				Type:      "test",
				CreatedAt: now,
				Payload: &pb.CredentialLibrary{
					Id:                "id",
					CredentialStoreId: "credential-store-id",
					Scope: &scopes.ScopeInfo{
						Id:            "scope-id",
						Type:          "scope-type",
						Name:          "scope-name",
						Description:   "scope-descriptione",
						ParentScopeId: "scope-parent-scope-id",
					},
					Name:        &wrapperspb.StringValue{Value: "name"},
					Description: &wrapperspb.StringValue{Value: "description"},
					CreatedTime: pbNow,
					UpdatedTime: pbNow,
					Version:     1,
					Type:        "default",
					Attrs: &pb.CredentialLibrary_Attributes{
						Attributes: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								"field1": structpb.NewStringValue(encrypt.RedactedData),
								"field2": structpb.NewStringValue(encrypt.RedactedData),
							},
						},
					},
					AuthorizedActions: []string{"action-1", "action-2"},
					CredentialType:    "credential-type",
					CredentialMappingOverrides: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"override-1": structpb.NewStringValue(encrypt.RedactedData),
							"override-2": structpb.NewStringValue(encrypt.RedactedData),
						},
					},
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wantJSON, err := json.Marshal(tc.want)
			require.NoError(t, err)

			got, err := testEncryptingFilter.Process(ctx, tc.in)
			require.NoError(t, err)
			require.NotNil(t, got)
			gotJSON, err := json.Marshal(got)
			require.NoError(t, err)
			assert.JSONEq(t, string(wantJSON), string(gotJSON))
		})
	}
}
