package authmethods

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/hashicorp/boundary/sdk/pbs/controller/api"
	"github.com/hashicorp/boundary/sdk/wrapper"
	"github.com/hashicorp/eventlogger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func TestAuthMethod_Tags(t *testing.T) {
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
			name: "validate-oidc-filtering",
			testEvent: &eventlogger.Event{
				Type:      "test",
				CreatedAt: now,
				Payload: &AuthMethod{
					Id:          "id",
					ScopeId:     "scope-id",
					Name:        &wrapperspb.StringValue{Value: "name"},
					Description: &wrapperspb.StringValue{Value: "description"},
					Type:        "oidc",
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"state":                                structpb.NewStringValue("public-state"),
							"issuer":                               structpb.NewStringValue("public-issuer"),
							"client_id":                            structpb.NewStringValue("public-client_id"),
							"client_secret_hmac":                   structpb.NewStringValue("public-client_secret_hmac"),
							"max_age":                              structpb.NewStringValue("public-max_age"),
							"signing_algorithms":                   structpb.NewStringValue("public-signing_algorithms"),
							"idp_ca_certs":                         structpb.NewStringValue("public-signing_algorithms"),
							"api_url_prefix":                       structpb.NewStringValue("public-api_url_prefix"),
							"callback_url":                         structpb.NewStringValue("public-callback_url"),
							"allowed_audiences":                    structpb.NewStringValue("public-allowed_audiences"),
							"claims_scopes":                        structpb.NewStringValue("public-claims_scopes"),
							"account_claim_maps":                   structpb.NewStringValue("public-account_claim_maps"),
							"disable_discovered_config_validation": structpb.NewStringValue("public-disable_discovered_config_validation"),
							"dry_run":                              structpb.NewStringValue("public-dry_run"),
							"client_secret":                        structpb.NewStringValue("secret-client_secret"),
						},
					},
					AuthorizedActions: []string{"action-1", "action-2"},
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
				Payload: &AuthMethod{
					Id:          "id",
					ScopeId:     "scope-id",
					Name:        &wrapperspb.StringValue{Value: "name"},
					Description: &wrapperspb.StringValue{Value: "description"},
					Type:        "oidc",
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"state":                                structpb.NewStringValue("public-state"),
							"issuer":                               structpb.NewStringValue("public-issuer"),
							"client_id":                            structpb.NewStringValue("public-client_id"),
							"client_secret_hmac":                   structpb.NewStringValue("public-client_secret_hmac"),
							"max_age":                              structpb.NewStringValue("public-max_age"),
							"signing_algorithms":                   structpb.NewStringValue("public-signing_algorithms"),
							"idp_ca_certs":                         structpb.NewStringValue("public-signing_algorithms"),
							"api_url_prefix":                       structpb.NewStringValue("public-api_url_prefix"),
							"callback_url":                         structpb.NewStringValue("public-callback_url"),
							"allowed_audiences":                    structpb.NewStringValue("public-allowed_audiences"),
							"claims_scopes":                        structpb.NewStringValue("public-claims_scopes"),
							"account_claim_maps":                   structpb.NewStringValue("public-account_claim_maps"),
							"disable_discovered_config_validation": structpb.NewStringValue("public-disable_discovered_config_validation"),
							"dry_run":                              structpb.NewStringValue("public-dry_run"),
							"client_secret":                        structpb.NewStringValue("<REDACTED>"),
						},
					},
					AuthorizedActions: []string{"action-1", "action-2"},
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
		{
			name: "validate-password-filtering",
			testEvent: &eventlogger.Event{
				Type:      "test",
				CreatedAt: now,
				Payload: &AuthMethod{
					Id:          "id",
					ScopeId:     "scope-id",
					Name:        &wrapperspb.StringValue{Value: "name"},
					Description: &wrapperspb.StringValue{Value: "description"},
					Type:        "password",
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"min_login_name_length": structpb.NewStringValue("public-min_login_name_length"),
							"min_password_length":   structpb.NewStringValue("public-min_password_length"),
						},
					},
					AuthorizedActions: []string{"action-1", "action-2"},
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
				Payload: &AuthMethod{
					Id:          "id",
					ScopeId:     "scope-id",
					Name:        &wrapperspb.StringValue{Value: "name"},
					Description: &wrapperspb.StringValue{Value: "description"},
					Type:        "password",
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"min_login_name_length": structpb.NewStringValue("public-min_login_name_length"),
							"min_password_length":   structpb.NewStringValue("public-min_password_length"),
						},
					},
					AuthorizedActions: []string{"action-1", "action-2"},
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
