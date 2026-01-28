// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: MPL-2.0

package scopes

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/hashicorp/boundary/sdk/wrapper"
	"github.com/hashicorp/eventlogger"
	"github.com/hashicorp/eventlogger/filters/encrypt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func TestScope_Tags(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	wrapper := wrapper.TestWrapper(t)
	testEncryptingFilter := &encrypt.Filter{
		Wrapper:  wrapper,
		HmacSalt: []byte("salt"),
		HmacInfo: []byte("info"),
	}

	tests := []struct {
		name      string
		testEvent *eventlogger.Event
		wantEvent *eventlogger.Event
	}{
		{
			name: "validate-filtering",
			testEvent: &eventlogger.Event{
				Type:      "test",
				CreatedAt: now,
				Payload: &Scope{
					Id:                  "id",
					ScopeId:             "scope-id",
					Name:                &wrapperspb.StringValue{Value: "name"},
					Description:         &wrapperspb.StringValue{Value: "description"},
					Type:                "type",
					PrimaryAuthMethodId: &wrapperspb.StringValue{Value: "primary-auth-method-id"},
					AuthorizedActions:   []string{"action-1", "action-2"},
					AuthorizedCollectionActions: map[string]*structpb.ListValue{
						"auth-methods": {
							Values: []*structpb.Value{
								structpb.NewStringValue("create"),
								structpb.NewStringValue("list"),
							},
						},
					},
				},
			},
			wantEvent: &eventlogger.Event{
				Type:      "test",
				CreatedAt: now,
				Payload: &Scope{
					Id:                  "id",
					ScopeId:             "scope-id",
					Name:                &wrapperspb.StringValue{Value: "name"},
					Description:         &wrapperspb.StringValue{Value: "description"},
					Type:                "type",
					PrimaryAuthMethodId: &wrapperspb.StringValue{Value: "primary-auth-method-id"},
					AuthorizedActions:   []string{"action-1", "action-2"},
					AuthorizedCollectionActions: map[string]*structpb.ListValue{
						"auth-methods": {
							Values: []*structpb.Value{
								structpb.NewStringValue("create"),
								structpb.NewStringValue("list"),
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
