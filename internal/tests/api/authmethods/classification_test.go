// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package authmethods_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/hashicorp/boundary/sdk/pbs/controller/api"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/authmethods"
	"github.com/hashicorp/boundary/sdk/wrapper"
	"github.com/hashicorp/eventlogger"
	"github.com/hashicorp/eventlogger/filters/encrypt"
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
			name: "validate-oidc-filtering",
			testEvent: &eventlogger.Event{
				Type:      "test",
				CreatedAt: now,
				Payload: &pb.AuthMethod{
					Id:          "id",
					ScopeId:     "scope-id",
					Name:        &wrapperspb.StringValue{Value: "name"},
					Description: &wrapperspb.StringValue{Value: "description"},
					Type:        "oidc",
					Attrs: &pb.AuthMethod_OidcAuthMethodsAttributes{
						OidcAuthMethodsAttributes: &pb.OidcAuthMethodAttributes{
							State:                             "public-state",
							Issuer:                            wrapperspb.String("public-issuer"),
							ClientId:                          wrapperspb.String("public-client_id"),
							ClientSecretHmac:                  "public-client_secret_hmac",
							MaxAge:                            wrapperspb.UInt32(100),
							SigningAlgorithms:                 []string{"public-signing_algorithms"},
							IdpCaCerts:                        []string{"public-idp_ca_certs"},
							ApiUrlPrefix:                      wrapperspb.String("public-api_url_prefix"),
							CallbackUrl:                       "public-callback_url",
							AllowedAudiences:                  []string{"public-allowed_audiences"},
							ClaimsScopes:                      []string{"public-claims_scopes"},
							AccountClaimMaps:                  []string{"public-account_claim_maps"},
							DisableDiscoveredConfigValidation: false,
							DryRun:                            false,
							ClientSecret:                      wrapperspb.String("secret-client_secret"),
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
				Payload: &pb.AuthMethod{
					Id:          "id",
					ScopeId:     "scope-id",
					Name:        &wrapperspb.StringValue{Value: "name"},
					Description: &wrapperspb.StringValue{Value: "description"},
					Type:        "oidc",
					Attrs: &pb.AuthMethod_OidcAuthMethodsAttributes{
						OidcAuthMethodsAttributes: &pb.OidcAuthMethodAttributes{
							State:                             "public-state",
							Issuer:                            wrapperspb.String("public-issuer"),
							ClientId:                          wrapperspb.String("public-client_id"),
							ClientSecretHmac:                  "public-client_secret_hmac",
							MaxAge:                            wrapperspb.UInt32(100),
							SigningAlgorithms:                 []string{"public-signing_algorithms"},
							IdpCaCerts:                        []string{"public-idp_ca_certs"},
							ApiUrlPrefix:                      wrapperspb.String("public-api_url_prefix"),
							CallbackUrl:                       "public-callback_url",
							AllowedAudiences:                  []string{"public-allowed_audiences"},
							ClaimsScopes:                      []string{"public-claims_scopes"},
							AccountClaimMaps:                  []string{"public-account_claim_maps"},
							DisableDiscoveredConfigValidation: false,
							DryRun:                            false,
							ClientSecret:                      wrapperspb.String(encrypt.RedactedData),
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
				Payload: &pb.AuthMethod{
					Id:          "id",
					ScopeId:     "scope-id",
					Name:        &wrapperspb.StringValue{Value: "name"},
					Description: &wrapperspb.StringValue{Value: "description"},
					Type:        "password",
					Attrs: &pb.AuthMethod_PasswordAuthMethodAttributes{
						PasswordAuthMethodAttributes: &pb.PasswordAuthMethodAttributes{
							MinLoginNameLength: 100,
							MinPasswordLength:  100,
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
				Payload: &pb.AuthMethod{
					Id:          "id",
					ScopeId:     "scope-id",
					Name:        &wrapperspb.StringValue{Value: "name"},
					Description: &wrapperspb.StringValue{Value: "description"},
					Type:        "password",
					Attrs: &pb.AuthMethod_PasswordAuthMethodAttributes{
						PasswordAuthMethodAttributes: &pb.PasswordAuthMethodAttributes{
							MinLoginNameLength: 100,
							MinPasswordLength:  100,
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
			name: "validate-ldap-filtering",
			testEvent: &eventlogger.Event{
				Type:      "test",
				CreatedAt: now,
				Payload: &pb.AuthMethod{
					Id:          "id",
					ScopeId:     "scope-id",
					Name:        &wrapperspb.StringValue{Value: "name"},
					Description: &wrapperspb.StringValue{Value: "description"},
					Type:        "ldap",
					Attrs: &pb.AuthMethod_LdapAuthMethodsAttributes{
						LdapAuthMethodsAttributes: &pb.LdapAuthMethodAttributes{
							StartTls:                 true,
							InsecureTls:              true,
							DiscoverDn:               true,
							AnonGroupSearch:          true,
							UpnDomain:                wrapperspb.String("upn-domain"),
							Urls:                     []string{"ldaps://ldap1"},
							UserDn:                   wrapperspb.String("user-dn"),
							UserAttr:                 wrapperspb.String("user-attr"),
							UserFilter:               wrapperspb.String("user-filter"),
							EnableGroups:             true,
							GroupDn:                  wrapperspb.String("group-dn"),
							GroupAttr:                wrapperspb.String("group-attr"),
							GroupFilter:              wrapperspb.String("group-filter"),
							Certificates:             []string{"certs"},
							ClientCertificate:        wrapperspb.String("client-cert"),
							ClientCertificateKey:     wrapperspb.String("client-cert-key"),
							ClientCertificateKeyHmac: "client-cert-key-hmac",
							BindDn:                   wrapperspb.String("bind-dn"),
							BindPassword:             wrapperspb.String("bind-password"),
							BindPasswordHmac:         "bind-password-hmac",
							UseTokenGroups:           true,
							AccountAttributeMaps:     []string{"map1"},
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
				Payload: &pb.AuthMethod{
					Id:          "id",
					ScopeId:     "scope-id",
					Name:        &wrapperspb.StringValue{Value: "name"},
					Description: &wrapperspb.StringValue{Value: "description"},
					Type:        "ldap",
					Attrs: &pb.AuthMethod_LdapAuthMethodsAttributes{
						LdapAuthMethodsAttributes: &pb.LdapAuthMethodAttributes{
							StartTls:                 true,
							InsecureTls:              true,
							DiscoverDn:               true,
							AnonGroupSearch:          true,
							UpnDomain:                wrapperspb.String("upn-domain"),
							Urls:                     []string{"ldaps://ldap1"},
							UserDn:                   wrapperspb.String("user-dn"),
							UserAttr:                 wrapperspb.String("user-attr"),
							UserFilter:               wrapperspb.String("user-filter"),
							EnableGroups:             true,
							GroupDn:                  wrapperspb.String("group-dn"),
							GroupAttr:                wrapperspb.String("group-attr"),
							GroupFilter:              wrapperspb.String("group-filter"),
							Certificates:             []string{"certs"},
							ClientCertificate:        wrapperspb.String("client-cert"),
							ClientCertificateKey:     wrapperspb.String(encrypt.RedactedData),
							ClientCertificateKeyHmac: "client-cert-key-hmac",
							BindDn:                   wrapperspb.String("bind-dn"),
							BindPassword:             wrapperspb.String(encrypt.RedactedData),
							BindPasswordHmac:         "bind-password-hmac",
							UseTokenGroups:           true,
							AccountAttributeMaps:     []string{"map1"},
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
