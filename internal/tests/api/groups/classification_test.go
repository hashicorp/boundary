// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package groups_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/hashicorp/boundary/sdk/pbs/controller/api"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/groups"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/scopes"
	"github.com/hashicorp/boundary/sdk/wrapper"
	"github.com/hashicorp/eventlogger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func TestGroupsClassification(t *testing.T) {
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
			name: "validate-group-filtering",
			in: &eventlogger.Event{
				Type:      "test",
				CreatedAt: now,
				Payload: &pb.Group{
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
					Version:     1,
					MemberIds:   []string{"member-id"},
					Members: []*pb.Member{
						{
							Id:      "member-id",
							ScopeId: "scope-id",
						},
					},
					AuthorizedActions: []string{
						"action-1",
						"action-2",
					},
				},
			},
			want: &eventlogger.Event{
				Type:      "test",
				CreatedAt: now,
				Payload: &pb.Group{
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
					Version:     1,
					MemberIds:   []string{"member-id"},
					Members: []*pb.Member{
						{
							Id:      "member-id",
							ScopeId: "scope-id",
						},
					},
					AuthorizedActions: []string{
						"action-1",
						"action-2",
					},
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := testEncryptingFilter.Process(ctx, tc.in)
			require.NoError(err)
			require.NotNil(got)
			gotJSON, err := json.Marshal(got)
			require.NoError(err)

			wantJSON, err := json.Marshal(tc.want)
			require.NoError(err)
			assert.JSONEq(string(wantJSON), string(gotJSON))
		})
	}
}
