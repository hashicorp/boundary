// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package roles_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/roles"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/scopes"
	"github.com/hashicorp/boundary/sdk/wrapper"
	"github.com/hashicorp/eventlogger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func TestRoles(t *testing.T) {
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
			name: "role",
			in: &eventlogger.Event{
				Type:      "test",
				CreatedAt: now,
				Payload: &pb.Role{
					Id:      "id",
					ScopeId: "scope-id",
					Scope: &scopes.ScopeInfo{
						Id:            "scope-id",
						Type:          "scope-type",
						Name:          "scope-name",
						Description:   "scope-description",
						ParentScopeId: "scope-parent-scope-id",
					},
					Name:        &wrapperspb.StringValue{Value: "name"},
					Description: &wrapperspb.StringValue{Value: "description"},
					CreatedTime: pbNow,
					UpdatedTime: pbNow,
					Version:     0,
					GrantScopeIds: []string{
						globals.GrantScopeThis,
						"grant-scope-id",
					},
					PrincipalIds: []string{
						"principal-id",
					},
					Principals: []*pb.Principal{
						{
							Id:      "principal-id",
							Type:    "principal-type",
							ScopeId: "principal-scope-id",
						},
					},
					GrantStrings: []string{
						"grand-string",
					},
					Grants: []*pb.Grant{
						{
							Raw:       "raw",
							Canonical: "canonical",
							Json: &pb.GrantJson{
								Id:      "grant-json-id",
								Type:    "grant-json-type",
								Actions: []string{"action"},
							},
						},
					},
					AuthorizedActions: []string{"action-1"},
				},
			},
			want: &eventlogger.Event{
				Type:      "test",
				CreatedAt: now,
				Payload: &pb.Role{
					Id:      "id",
					ScopeId: "scope-id",
					Scope: &scopes.ScopeInfo{
						Id:            "scope-id",
						Type:          "scope-type",
						Name:          "scope-name",
						Description:   "scope-description",
						ParentScopeId: "scope-parent-scope-id",
					},
					Name:        &wrapperspb.StringValue{Value: "name"},
					Description: &wrapperspb.StringValue{Value: "description"},
					CreatedTime: pbNow,
					UpdatedTime: pbNow,
					Version:     0,
					GrantScopeIds: []string{
						globals.GrantScopeThis,
						"grant-scope-id",
					},
					PrincipalIds: []string{
						"principal-id",
					},
					Principals: []*pb.Principal{
						{
							Id:      "principal-id",
							Type:    "principal-type",
							ScopeId: "principal-scope-id",
						},
					},
					GrantStrings: []string{
						"grand-string",
					},
					Grants: []*pb.Grant{
						{
							Raw:       "raw",
							Canonical: "canonical",
							Json: &pb.GrantJson{
								Id:      "grant-json-id",
								Type:    "grant-json-type",
								Actions: []string{"action"},
							},
						},
					},
					AuthorizedActions: []string{"action-1"},
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
