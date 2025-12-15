// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package users_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/hashicorp/boundary/sdk/pbs/controller/api"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/scopes"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/users"
	"github.com/hashicorp/boundary/sdk/wrapper"
	"github.com/hashicorp/eventlogger"
	"github.com/hashicorp/eventlogger/filters/encrypt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func TestUsers(t *testing.T) {
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
			name: "role",
			in: &eventlogger.Event{
				Type:      "test",
				CreatedAt: now,
				Payload: &pb.User{
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
					AccountIds:  []string{"account-id"},
					Accounts: []*pb.Account{
						{
							Id:      "account-id",
							ScopeId: "scope-id",
						},
					},
					AuthorizedActions: []string{"action-1"},
					LoginName:         "login-name",
					FullName:          "full-name",
					Email:             "email@test.test",
					PrimaryAccountId:  "primary-account-id",
				},
			},
			want: &eventlogger.Event{
				Type:      "test",
				CreatedAt: now,
				Payload: &pb.User{
					Id:      "id",
					ScopeId: "scope-id",
					Scope: &scopes.ScopeInfo{
						Id:            "scope-id",
						Type:          "scope-type",
						Name:          "scope-name",
						Description:   "scope-description",
						ParentScopeId: "scope-parent-scope-id",
					},
					Name:        &wrapperspb.StringValue{Value: encrypt.TestHmacSha256(t, []byte("name"), wrapper, nil, nil)},
					Description: &wrapperspb.StringValue{Value: encrypt.TestHmacSha256(t, []byte("description"), wrapper, nil, nil)},
					CreatedTime: pbNow,
					UpdatedTime: pbNow,
					Version:     0,
					AccountIds:  []string{"account-id"},
					Accounts: []*pb.Account{
						{
							Id:      "account-id",
							ScopeId: "scope-id",
						},
					},
					AuthorizedActions: []string{"action-1"},
					LoginName:         encrypt.TestHmacSha256(t, []byte("login-name"), wrapper, nil, nil),
					FullName:          encrypt.TestHmacSha256(t, []byte("full-name"), wrapper, nil, nil),
					Email:             encrypt.TestHmacSha256(t, []byte("email@test.test"), wrapper, nil, nil),
					PrimaryAccountId:  "primary-account-id",
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
