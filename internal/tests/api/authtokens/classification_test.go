// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package authtokens_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/hashicorp/boundary/sdk/pbs/controller/api"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/authtokens"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/scopes"
	"github.com/hashicorp/boundary/sdk/wrapper"
	"github.com/hashicorp/eventlogger"
	"github.com/hashicorp/eventlogger/filters/encrypt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestAuthtokenClassification(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	wrapper := wrapper.TestWrapper(t)
	testEncryptingFilter := api.NewEncryptFilter(t, wrapper)

	tests := []struct {
		name      string
		testEvent *eventlogger.Event
		wantEvent *eventlogger.Event
	}{
		{
			name: "validate-authtoken-filtering",
			testEvent: &eventlogger.Event{
				Type:      "test",
				CreatedAt: now,
				Payload: &pb.AuthToken{
					AccountId:               "public-account_id",
					ApproximateLastUsedTime: timestamppb.New(now),
					AuthMethodId:            "public-auth_method_id",
					AuthorizedActions: []string{
						"public-authorized_actions",
					},
					CreatedTime:    timestamppb.New(now),
					ExpirationTime: timestamppb.New(now),
					Id:             "public-id",
					ScopeId:        "public-scope_id",
					Scope: &scopes.ScopeInfo{
						Id:            "public-scope_id",
						Type:          "public-scope_type",
						Name:          "public-scope_name",
						Description:   "public-scope_description",
						ParentScopeId: "public-parent_scope_id",
					},
					UpdatedTime: timestamppb.New(now),
					UserId:      "public-user_id",
					Token:       "secret-token",
				},
			},
			wantEvent: &eventlogger.Event{
				Type:      "test",
				CreatedAt: now,
				Payload: &pb.AuthToken{
					AccountId:               "public-account_id",
					ApproximateLastUsedTime: timestamppb.New(now),
					AuthMethodId:            "public-auth_method_id",
					AuthorizedActions: []string{
						"public-authorized_actions",
					},
					CreatedTime:    timestamppb.New(now),
					ExpirationTime: timestamppb.New(now),
					Id:             "public-id",
					ScopeId:        "public-scope_id",
					Scope: &scopes.ScopeInfo{
						Id:            "public-scope_id",
						Type:          "public-scope_type",
						Name:          "public-scope_name",
						Description:   "public-scope_description",
						ParentScopeId: "public-parent_scope_id",
					},
					UpdatedTime: timestamppb.New(now),
					UserId:      "public-user_id",
					Token:       encrypt.RedactedData,
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
