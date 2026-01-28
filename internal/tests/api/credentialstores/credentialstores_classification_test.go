// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package credentialstores_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/hashicorp/boundary/sdk/pbs/controller/api"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/credentialstores"
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

func TestCredentialStoreClassification(t *testing.T) {
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
				Payload: &pb.CredentialStore{
					Id:      "id",
					ScopeId: "scope-id",
					Scope: &scopes.ScopeInfo{
						Id:            "scope-id",
						Type:          "scope-type",
						Name:          "scope-name",
						Description:   "scope-descriptione",
						ParentScopeId: "scope-parent-scope-id",
					},
					Name: &wrapperspb.StringValue{
						Value: "name",
					},
					Description: &wrapperspb.StringValue{
						Value: "description",
					},
					CreatedTime: pbNow,
					UpdatedTime: pbNow,
					Version:     1,
					Type:        "vault",
					Attrs: &pb.CredentialStore_VaultCredentialStoreAttributes{
						VaultCredentialStoreAttributes: &pb.VaultCredentialStoreAttributes{
							Address:                  &wrapperspb.StringValue{Value: "address"},
							Namespace:                &wrapperspb.StringValue{Value: "namespace"},
							CaCert:                   &wrapperspb.StringValue{Value: "ca-cert"},
							TlsServerName:            &wrapperspb.StringValue{Value: "tls-server-name"},
							TlsSkipVerify:            &wrapperspb.BoolValue{Value: true},
							Token:                    &wrapperspb.StringValue{Value: "token"},
							TokenHmac:                "token-hmac",
							ClientCertificate:        &wrapperspb.StringValue{Value: "client-certificate"},
							ClientCertificateKey:     &wrapperspb.StringValue{Value: "client-certificate-key"},
							ClientCertificateKeyHmac: "client-certificate-key-hmac",
						},
					},
					AuthorizedActions: []string{
						"action-1",
						"action-2",
					},
					AuthorizedCollectionActions: map[string]*structpb.ListValue{
						"action-1": {Values: []*structpb.Value{structpb.NewStringValue("value-1")}},
					},
				},
			},
			&eventlogger.Event{
				Type:      "test",
				CreatedAt: now,
				Payload: &pb.CredentialStore{
					Id:      "id",
					ScopeId: "scope-id",
					Scope: &scopes.ScopeInfo{
						Id:            "scope-id",
						Type:          "scope-type",
						Name:          "scope-name",
						Description:   "scope-descriptione",
						ParentScopeId: "scope-parent-scope-id",
					},
					Name: &wrapperspb.StringValue{
						Value: "name",
					},
					Description: &wrapperspb.StringValue{
						Value: "description",
					},
					CreatedTime: pbNow,
					UpdatedTime: pbNow,
					Version:     1,
					Type:        "vault",
					Attrs: &pb.CredentialStore_VaultCredentialStoreAttributes{
						VaultCredentialStoreAttributes: &pb.VaultCredentialStoreAttributes{
							Address:                  &wrapperspb.StringValue{Value: "address"},
							Namespace:                &wrapperspb.StringValue{Value: "namespace"},
							CaCert:                   &wrapperspb.StringValue{Value: "ca-cert"},
							TlsServerName:            &wrapperspb.StringValue{Value: "tls-server-name"},
							TlsSkipVerify:            &wrapperspb.BoolValue{Value: true},
							Token:                    &wrapperspb.StringValue{Value: encrypt.RedactedData},
							TokenHmac:                "token-hmac",
							ClientCertificate:        &wrapperspb.StringValue{Value: encrypt.RedactedData},
							ClientCertificateKey:     &wrapperspb.StringValue{Value: encrypt.RedactedData},
							ClientCertificateKeyHmac: "client-certificate-key-hmac",
						},
					},
					AuthorizedActions: []string{
						"action-1",
						"action-2",
					},
					AuthorizedCollectionActions: map[string]*structpb.ListValue{
						"action-1": {Values: []*structpb.Value{structpb.NewStringValue("value-1")}},
					},
				},
			},
		},
		{
			"Default",
			&eventlogger.Event{
				Type:      "test",
				CreatedAt: now,
				Payload: &pb.CredentialStore{
					Id:      "id",
					ScopeId: "scope-id",
					Scope: &scopes.ScopeInfo{
						Id:            "scope-id",
						Type:          "scope-type",
						Name:          "scope-name",
						Description:   "scope-descriptione",
						ParentScopeId: "scope-parent-scope-id",
					},
					Name: &wrapperspb.StringValue{
						Value: "name",
					},
					Description: &wrapperspb.StringValue{
						Value: "description",
					},
					CreatedTime: pbNow,
					UpdatedTime: pbNow,
					Version:     1,
					Type:        "vault",
					Attrs: &pb.CredentialStore_Attributes{
						Attributes: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								"field1": structpb.NewStringValue("value-1"),
								"field2": structpb.NewStringValue("value-2"),
							},
						},
					},
					AuthorizedActions: []string{
						"action-1",
						"action-2",
					},
					AuthorizedCollectionActions: map[string]*structpb.ListValue{
						"action-1": {Values: []*structpb.Value{structpb.NewStringValue("value-1")}},
					},
				},
			},
			&eventlogger.Event{
				Type:      "test",
				CreatedAt: now,
				Payload: &pb.CredentialStore{
					Id:      "id",
					ScopeId: "scope-id",
					Scope: &scopes.ScopeInfo{
						Id:            "scope-id",
						Type:          "scope-type",
						Name:          "scope-name",
						Description:   "scope-descriptione",
						ParentScopeId: "scope-parent-scope-id",
					},
					Name: &wrapperspb.StringValue{
						Value: "name",
					},
					Description: &wrapperspb.StringValue{
						Value: "description",
					},
					CreatedTime: pbNow,
					UpdatedTime: pbNow,
					Version:     1,
					Type:        "vault",
					Attrs: &pb.CredentialStore_Attributes{
						Attributes: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								"field1": structpb.NewStringValue(encrypt.RedactedData),
								"field2": structpb.NewStringValue(encrypt.RedactedData),
							},
						},
					},
					AuthorizedActions: []string{
						"action-1",
						"action-2",
					},
					AuthorizedCollectionActions: map[string]*structpb.ListValue{
						"action-1": {Values: []*structpb.Value{structpb.NewStringValue("value-1")}},
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
