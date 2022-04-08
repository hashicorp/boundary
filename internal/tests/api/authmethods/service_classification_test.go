package authmethods_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api"
	"github.com/hashicorp/boundary/sdk/wrapper"
	"github.com/hashicorp/eventlogger"
	"github.com/hashicorp/eventlogger/filters/encrypt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	structpb "google.golang.org/protobuf/types/known/structpb"
)

// TestAuthenticate_Tags will test that the response filtering aligns with the
// AuthenticateResponse and AuthenticateResponse tags.  See:
// internal/tests/api/authmethods/authenticate_test.go TestAuthenticate where
// the audit events produced using these tags is unit tested.
func TestAuthenticate_Tags(t *testing.T) {
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
			name: "validate-response-filtering",
			testEvent: &eventlogger.Event{
				Type:      "test",
				CreatedAt: now,
				Payload: &services.AuthenticateResponse{
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
							"type":                       structpb.NewStringValue("public-type"),
							"updated_time":               structpb.NewStringValue("public-updated_time"),
							"user_id":                    structpb.NewStringValue("public-user_id"),
							"status":                     structpb.NewStringValue("public-status"),
							"auth_url":                   structpb.NewStringValue("public-auth_url"),
							"token_id":                   structpb.NewStringValue("public-token_id"),
							"final_redirect_url":         structpb.NewStringValue("public-final_redirect_url"),
							"token":                      structpb.NewStringValue("secret-token"),
						},
					},
				},
			},
			wantEvent: &eventlogger.Event{
				Type:      "test",
				CreatedAt: now,
				Payload: &services.AuthenticateResponse{
					Command: "public-command",
					// TODO(johanbrandhorst): update redaction once typed attributes are available
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"account_id":                 structpb.NewStringValue(encrypt.RedactedData),
							"approximate_last_used_time": structpb.NewStringValue(encrypt.RedactedData),
							"auth_method_id":             structpb.NewStringValue(encrypt.RedactedData),
							"authorized_actions":         structpb.NewStringValue(encrypt.RedactedData),
							"created_time":               structpb.NewStringValue(encrypt.RedactedData),
							"expiration_time":            structpb.NewStringValue(encrypt.RedactedData),
							"id":                         structpb.NewStringValue(encrypt.RedactedData),
							"scope":                      structpb.NewStringValue(encrypt.RedactedData),
							"type":                       structpb.NewStringValue(encrypt.RedactedData),
							"updated_time":               structpb.NewStringValue(encrypt.RedactedData),
							"user_id":                    structpb.NewStringValue(encrypt.RedactedData),
							"status":                     structpb.NewStringValue(encrypt.RedactedData),
							"auth_url":                   structpb.NewStringValue(encrypt.RedactedData),
							"token_id":                   structpb.NewStringValue(encrypt.RedactedData),
							"final_redirect_url":         structpb.NewStringValue(encrypt.RedactedData),
							"token":                      structpb.NewStringValue(encrypt.RedactedData),
						},
					},
				},
			},
		},
		{
			name: "validate-request-filtering",
			testEvent: &eventlogger.Event{
				Type:      "test",
				CreatedAt: now,
				Payload: &services.AuthenticateRequest{
					AuthMethodId: "public-auth-method-id",
					TokenType:    "public-token-type",
					Command:      "public-command",
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"login_name": structpb.NewStringValue("public-login_name"),
							"auth_url":   structpb.NewStringValue("public-auth_url"),
							"token_id":   structpb.NewStringValue("public-token_id"),
							"state":      structpb.NewStringValue("public-state"),
							"password":   structpb.NewStringValue("secret-password"),
							"code":       structpb.NewStringValue("secret-code"),
						},
					},
				},
			},
			wantEvent: &eventlogger.Event{
				Type:      "test",
				CreatedAt: now,
				Payload: &services.AuthenticateRequest{
					AuthMethodId: "public-auth-method-id",
					TokenType:    "public-token-type",
					Command:      "public-command",
					// TODO(johanbrandhorst): update redaction once typed attributes are available
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"login_name": structpb.NewStringValue(encrypt.RedactedData),
							"auth_url":   structpb.NewStringValue(encrypt.RedactedData),
							"token_id":   structpb.NewStringValue(encrypt.RedactedData),
							"state":      structpb.NewStringValue(encrypt.RedactedData),
							"password":   structpb.NewStringValue(encrypt.RedactedData),
							"code":       structpb.NewStringValue(encrypt.RedactedData),
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
