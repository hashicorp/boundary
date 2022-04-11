package authmethods_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/authmethods"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/scopes"
	"github.com/hashicorp/boundary/sdk/wrapper"
	"github.com/hashicorp/eventlogger"
	"github.com/hashicorp/eventlogger/filters/encrypt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
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
					Attrs: &services.AuthenticateResponse_AuthTokenResponse{
						AuthTokenResponse: &authmethods.AuthTokenResponse{
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
							TokenType:   "public-token_type",
							UpdatedTime: timestamppb.New(now),
							UserId:      "public-user_id",
							Token:       "secret-token",
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
					Attrs: &services.AuthenticateResponse_AuthTokenResponse{
						AuthTokenResponse: &authmethods.AuthTokenResponse{
							AccountId:               encrypt.RedactedData,
							ApproximateLastUsedTime: timestamppb.New(now),
							AuthMethodId:            encrypt.RedactedData,
							AuthorizedActions: []string{
								encrypt.RedactedData,
							},
							CreatedTime:    timestamppb.New(now),
							ExpirationTime: timestamppb.New(now),
							Id:             encrypt.RedactedData,
							ScopeId:        encrypt.RedactedData,
							Scope: &scopes.ScopeInfo{
								Id:            "public-scope_id",
								Type:          "public-scope_type",
								Name:          "public-scope_name",
								Description:   "public-scope_description",
								ParentScopeId: "public-parent_scope_id",
							},
							TokenType:   encrypt.RedactedData,
							UpdatedTime: timestamppb.New(now),
							UserId:      encrypt.RedactedData,
							Token:       encrypt.RedactedData,
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
					Attrs: &services.AuthenticateRequest_OidcAuthMethodAuthenticateTokenRequest{
						OidcAuthMethodAuthenticateTokenRequest: &authmethods.OidcAuthMethodAuthenticateTokenRequest{
							TokenId: "public-token-id",
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
					Attrs: &services.AuthenticateRequest_OidcAuthMethodAuthenticateTokenRequest{
						OidcAuthMethodAuthenticateTokenRequest: &authmethods.OidcAuthMethodAuthenticateTokenRequest{
							TokenId: encrypt.RedactedData,
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
