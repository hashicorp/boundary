// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package authmethods_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/authmethods"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/authtokens"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/scopes"
	"github.com/hashicorp/boundary/sdk/wrapper"
	"github.com/hashicorp/eventlogger"
	"github.com/hashicorp/eventlogger/filters/encrypt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
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
			name: "validate-authenticate-request-filtering",
			testEvent: &eventlogger.Event{
				Type:      "test",
				CreatedAt: now,
				Payload: &services.AuthenticateRequest{
					AuthMethodId: "public-auth-method-id",
					TokenType:    "public-token-type",
					Command:      "public-command",
					Attrs: &services.AuthenticateRequest_OidcStartAttributes{
						OidcStartAttributes: &services.OidcStartAttributes{
							RoundtripPayload: &structpb.Struct{
								Fields: map[string]*structpb.Value{
									"key": structpb.NewStringValue("value"),
								},
							},
							CachedRoundtripPayload: "public-cached_roundtrip_payload",
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
					Attrs: &services.AuthenticateRequest_OidcStartAttributes{
						OidcStartAttributes: &services.OidcStartAttributes{
							RoundtripPayload: &structpb.Struct{
								Fields: map[string]*structpb.Value{
									"key": structpb.NewStringValue(encrypt.RedactedData),
								},
							},
							CachedRoundtripPayload: encrypt.TestHmacSha256(t, []byte("public-cached_roundtrip_payload"), wrapper, nil, nil),
						},
					},
				},
			},
		},
		{
			name: "validate-authenticate-response-filtering",
			testEvent: &eventlogger.Event{
				Type:      "test",
				CreatedAt: now,
				Payload: &services.AuthenticateResponse{
					Command: "public-command",
					Attrs: &services.AuthenticateResponse_AuthTokenResponse{
						AuthTokenResponse: &authtokens.AuthToken{
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
							Token:       "secret-type",
						},
					},
					Type: "public-type",
				},
			},
			wantEvent: &eventlogger.Event{
				Type:      "test",
				CreatedAt: now,
				Payload: &services.AuthenticateResponse{
					Command: "public-command",
					Attrs: &services.AuthenticateResponse_AuthTokenResponse{
						AuthTokenResponse: &authtokens.AuthToken{
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
					Type: "public-type",
				},
			},
		},
		{
			name: "validate-callback-request-filtering",
			testEvent: &eventlogger.Event{
				Type:      "test",
				CreatedAt: now,
				Payload: &services.AuthenticateRequest{
					AuthMethodId: "public-auth-method-id",
					TokenType:    "public-token-type",
					Command:      "public-command",
					Attrs: &services.AuthenticateRequest_OidcAuthMethodAuthenticateCallbackRequest{
						OidcAuthMethodAuthenticateCallbackRequest: &authmethods.OidcAuthMethodAuthenticateCallbackRequest{
							Code:             "secret-code",
							State:            "public-state",
							Error:            "public-error",
							ErrorDescription: "public-error_description",
							ErrorUri:         "public-error_uri",
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
					Attrs: &services.AuthenticateRequest_OidcAuthMethodAuthenticateCallbackRequest{
						OidcAuthMethodAuthenticateCallbackRequest: &authmethods.OidcAuthMethodAuthenticateCallbackRequest{
							Code:             encrypt.RedactedData,
							State:            "public-state",
							Error:            "public-error",
							ErrorDescription: "public-error_description",
							ErrorUri:         "public-error_uri",
						},
					},
				},
			},
		},
		{
			name: "validate-callback-response-filtering",
			testEvent: &eventlogger.Event{
				Type:      "test",
				CreatedAt: now,
				Payload: &services.AuthenticateResponse{
					Command: "public-command",
					Attrs: &services.AuthenticateResponse_OidcAuthMethodAuthenticateCallbackResponse{
						OidcAuthMethodAuthenticateCallbackResponse: &authmethods.OidcAuthMethodAuthenticateCallbackResponse{
							FinalRedirectUrl: "public-final_redirect_url",
						},
					},
				},
			},
			wantEvent: &eventlogger.Event{
				Type:      "test",
				CreatedAt: now,
				Payload: &services.AuthenticateResponse{
					Command: "public-command",
					Attrs: &services.AuthenticateResponse_OidcAuthMethodAuthenticateCallbackResponse{
						OidcAuthMethodAuthenticateCallbackResponse: &authmethods.OidcAuthMethodAuthenticateCallbackResponse{
							FinalRedirectUrl: "public-final_redirect_url",
						},
					},
				},
			},
		},
		{
			name: "validate-token-request-filtering",
			testEvent: &eventlogger.Event{
				Type:      "test",
				CreatedAt: now,
				Payload: &services.AuthenticateRequest{
					AuthMethodId: "public-auth-method-id",
					TokenType:    "public-token-type",
					Command:      "public-command",
					Attrs: &services.AuthenticateRequest_OidcAuthMethodAuthenticateTokenRequest{
						OidcAuthMethodAuthenticateTokenRequest: &authmethods.OidcAuthMethodAuthenticateTokenRequest{
							TokenId: "secret-token-id",
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
					Attrs: &services.AuthenticateRequest_OidcAuthMethodAuthenticateTokenRequest{
						OidcAuthMethodAuthenticateTokenRequest: &authmethods.OidcAuthMethodAuthenticateTokenRequest{
							TokenId: encrypt.RedactedData,
						},
					},
				},
			},
		},
		{
			name: "validate-token-response-filtering",
			testEvent: &eventlogger.Event{
				Type:      "test",
				CreatedAt: now,
				Payload: &services.AuthenticateResponse{
					Command: "public-command",
					Attrs: &services.AuthenticateResponse_OidcAuthMethodAuthenticateTokenResponse{
						OidcAuthMethodAuthenticateTokenResponse: &authmethods.OidcAuthMethodAuthenticateTokenResponse{
							Status: "public-status",
						},
					},
				},
			},
			wantEvent: &eventlogger.Event{
				Type:      "test",
				CreatedAt: now,
				Payload: &services.AuthenticateResponse{
					Command: "public-command",
					Attrs: &services.AuthenticateResponse_OidcAuthMethodAuthenticateTokenResponse{
						OidcAuthMethodAuthenticateTokenResponse: &authmethods.OidcAuthMethodAuthenticateTokenResponse{
							Status: "public-status",
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
