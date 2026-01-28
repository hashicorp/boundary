// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package hosts_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/hashicorp/boundary/sdk/pbs/controller/api"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/hosts"
	plugins "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/plugins"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/scopes"
	"github.com/hashicorp/boundary/sdk/wrapper"
	"github.com/hashicorp/eventlogger"
	"github.com/hashicorp/eventlogger/filters/encrypt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func TestClassification(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	wrapper := wrapper.TestWrapper(t)
	testEncryptingFilter := api.NewEncryptFilter(t, wrapper)
	testEncryptingFilter.FilterOperationOverrides = map[encrypt.DataClassification]encrypt.FilterOperation{
		// Use HMAC for sensitive fields for easy test comparisons
		encrypt.SensitiveClassification: encrypt.HmacSha256Operation,
	}

	tests := []struct {
		name      string
		testEvent *eventlogger.Event
		wantEvent *eventlogger.Event
	}{
		{
			name: "validate-response-filtering",
			testEvent: &eventlogger.Event{
				Type:      "test",
				CreatedAt: now,
				Payload: &pb.Host{
					Id: "public-id",
					Scope: &scopes.ScopeInfo{
						Id:            "public-scope_id",
						Type:          "public-scope_type",
						Name:          "public-scope_name",
						Description:   "public-scope_description",
						ParentScopeId: "public-parent_scope_id",
					},
					Plugin: &plugins.PluginInfo{
						Id:          "public-plugin_id",
						Name:        "public-plugin_name",
						Description: "public-plugin_description",
					},
					Name:        wrapperspb.String("public-name"),
					Description: wrapperspb.String("public-description"),
					CreatedTime: timestamppb.New(now),
					UpdatedTime: timestamppb.New(now),
					Version:     1,
					Type:        "public-type",
					Attrs: &pb.Host_StaticHostAttributes{
						StaticHostAttributes: &pb.StaticHostAttributes{
							Address: wrapperspb.String("public-address"),
						},
					},
					AuthorizedActions: []string{
						"public-action",
					},
					HostCatalogId: "public-host_catalog_id",
					HostSetIds: []string{
						"public-host_set_id",
					},
					IpAddresses: []string{
						"public-ip_address",
					},
					DnsNames: []string{
						"public-dns_name",
					},
					ExternalId: "public-external_id",
				},
			},
			wantEvent: &eventlogger.Event{
				Type:      "test",
				CreatedAt: now,
				Payload: &pb.Host{
					Id: "public-id",
					Scope: &scopes.ScopeInfo{
						Id:            "public-scope_id",
						Type:          "public-scope_type",
						Name:          "public-scope_name",
						Description:   "public-scope_description",
						ParentScopeId: "public-parent_scope_id",
					},
					Plugin: &plugins.PluginInfo{
						Id:          "public-plugin_id",
						Name:        "public-plugin_name",
						Description: "public-plugin_description",
					},
					Name:        wrapperspb.String("public-name"),
					Description: wrapperspb.String("public-description"),
					CreatedTime: timestamppb.New(now),
					UpdatedTime: timestamppb.New(now),
					Version:     1,
					Type:        "public-type",
					Attrs: &pb.Host_StaticHostAttributes{
						StaticHostAttributes: &pb.StaticHostAttributes{
							Address: wrapperspb.String("public-address"),
						},
					},
					AuthorizedActions: []string{
						"public-action",
					},
					HostCatalogId: "public-host_catalog_id",
					HostSetIds: []string{
						"public-host_set_id",
					},
					IpAddresses: []string{
						"public-ip_address",
					},
					DnsNames: []string{
						"public-dns_name",
					},
					ExternalId: "public-external_id",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := testEncryptingFilter.Process(ctx, tt.testEvent)
			require.NoError(err)
			require.NotNil(got)
			actualJson, err := json.Marshal(got)
			require.NoError(err)
			t.Log(string(actualJson))

			wantJson, err := json.Marshal(tt.wantEvent)
			require.NoError(err)
			assert.JSONEq(string(wantJson), string(actualJson))
		})
	}
}
