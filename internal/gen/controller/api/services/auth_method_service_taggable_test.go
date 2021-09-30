package services

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
	structpb "google.golang.org/protobuf/types/known/structpb"
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
				Payload: &AuthenticateResponse{
					Command: "public-command",
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"account_id":                 structpb.NewStringValue("public-account_id"),
							"approximate_last_used_time": structpb.NewStringValue("public-approximate_last_used_time"),
							"auth_method_id":             structpb.NewStringValue("public-auth_method_id"),
							"authorized_actions":         structpb.NewStringValue("public-authorized_actions"),
							"created_time":               structpb.NewStringValue("public-created_time"),
							"expiration_time":            structpb.NewStringValue("public-expiration_time"),
							"id":                         structpb.NewStringValue("public-id"),
							"scope":                      structpb.NewStringValue("public-scope"),
							"token_type":                 structpb.NewStringValue("public-token_type"),
							"updated_time":               structpb.NewStringValue("public-updated_time"),
							"user_id":                    structpb.NewStringValue("public-user_id"),
							"token":                      structpb.NewStringValue("secret-token"),
						},
					},
				},
			},
			wantEvent: &eventlogger.Event{
				Type:      "test",
				CreatedAt: now,
				Payload: &AuthenticateResponse{
					Command: "public-command",
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"account_id":                 structpb.NewStringValue("public-account_id"),
							"approximate_last_used_time": structpb.NewStringValue("public-approximate_last_used_time"),
							"auth_method_id":             structpb.NewStringValue("public-auth_method_id"),
							"authorized_actions":         structpb.NewStringValue("public-authorized_actions"),
							"created_time":               structpb.NewStringValue("public-created_time"),
							"expiration_time":            structpb.NewStringValue("public-expiration_time"),
							"id":                         structpb.NewStringValue("public-id"),
							"scope":                      structpb.NewStringValue("public-scope"),
							"token_type":                 structpb.NewStringValue("public-token_type"),
							"updated_time":               structpb.NewStringValue("public-updated_time"),
							"user_id":                    structpb.NewStringValue("public-user_id"),
							"token":                      structpb.NewStringValue("<REDACTED>"),
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
