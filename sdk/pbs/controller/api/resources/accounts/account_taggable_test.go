package accounts

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/hashicorp/boundary/sdk/pbs/controller/api"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/scopes"
	"github.com/hashicorp/boundary/sdk/wrapper"
	"github.com/hashicorp/eventlogger"
	"github.com/hashicorp/eventlogger/filters/encrypt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func TestTags(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name      string
		testEvent *eventlogger.Event
		wantEvent *eventlogger.Event
	}{
		{
			name: "ensure unspecified fields get redacted",
			testEvent: &eventlogger.Event{
				Type:      "test",
				CreatedAt: now,
				Payload: &Account{
					Id: "public-acc-id",
					Scope: &scopes.ScopeInfo{
						Id:            "public-scope-id",
						Type:          "public-scope-type",
						Name:          "public-scope-name",
						Description:   "public-scope-description",
						ParentScopeId: "public-parent-scopeid",
					},
					Name:         wrapperspb.String("public-name"),
					Description:  wrapperspb.String("public-description"),
					CreatedTime:  timestamppb.New(now),
					UpdatedTime:  timestamppb.New(now),
					Version:      1,
					Type:         "password",
					AuthMethodId: "public-auth-method-id",
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"hi": structpb.NewStringValue("some-random-value"),
						},
					},
				},
			},
			wantEvent: &eventlogger.Event{
				Type:      "test",
				CreatedAt: now,
				Payload: &Account{
					Id: "public-acc-id",
					Scope: &scopes.ScopeInfo{
						Id:            "public-scope-id",
						Type:          "public-scope-type",
						Name:          "public-scope-name",
						Description:   "public-scope-description",
						ParentScopeId: "public-parent-scopeid",
					},
					Name:         wrapperspb.String("public-name"),
					Description:  wrapperspb.String("public-description"),
					CreatedTime:  timestamppb.New(now),
					UpdatedTime:  timestamppb.New(now),
					Version:      1,
					Type:         "password",
					AuthMethodId: "public-auth-method-id",
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"hi": structpb.NewStringValue(encrypt.RedactedData),
						},
					},
				},
			},
		},
		{
			name: "password attributes",
			testEvent: &eventlogger.Event{
				Type:      "test",
				CreatedAt: now,
				Payload: &Account{
					Id: "public-acc-id",
					Scope: &scopes.ScopeInfo{
						Id:            "public-scope-id",
						Type:          "public-scope-type",
						Name:          "public-scope-name",
						Description:   "public-scope-description",
						ParentScopeId: "public-parent-scopeid",
					},
					Name:         wrapperspb.String("public-name"),
					Description:  wrapperspb.String("public-description"),
					CreatedTime:  timestamppb.New(now),
					UpdatedTime:  timestamppb.New(now),
					Version:      1,
					Type:         "password",
					AuthMethodId: "public-auth-method-id",
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"login_name": structpb.NewStringValue("public-login-name"),
							"password":   structpb.NewStringValue("secret-password"),
						},
					},
				},
			},
			wantEvent: &eventlogger.Event{
				Type:      "test",
				CreatedAt: now,
				Payload: &Account{
					Id: "public-acc-id",
					Scope: &scopes.ScopeInfo{
						Id:            "public-scope-id",
						Type:          "public-scope-type",
						Name:          "public-scope-name",
						Description:   "public-scope-description",
						ParentScopeId: "public-parent-scopeid",
					},
					Name:         wrapperspb.String("public-name"),
					Description:  wrapperspb.String("public-description"),
					CreatedTime:  timestamppb.New(now),
					UpdatedTime:  timestamppb.New(now),
					Version:      1,
					Type:         "password",
					AuthMethodId: "public-auth-method-id",
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"login_name": structpb.NewStringValue("public-login-name"),
							"password":   structpb.NewStringValue(encrypt.RedactedData),
						},
					},
				},
			},
		},
		{
			name: "oidc attributes with token and user info claims",
			testEvent: &eventlogger.Event{
				Type:      "test",
				CreatedAt: now,
				Payload: &Account{
					Id: "public-acc-id",
					Scope: &scopes.ScopeInfo{
						Id:            "public-scope-id",
						Type:          "public-scope-type",
						Name:          "public-scope-name",
						Description:   "public-scope-description",
						ParentScopeId: "public-parent-scopeid",
					},
					Name:         wrapperspb.String("public-name"),
					Description:  wrapperspb.String("public-description"),
					CreatedTime:  timestamppb.New(now),
					UpdatedTime:  timestamppb.New(now),
					Version:      1,
					Type:         "oidc",
					AuthMethodId: "public-auth-method-id",
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"issuer":    structpb.NewStringValue("public-issuer"),
							"subject":   structpb.NewStringValue("sensitive-subject"),
							"full_name": structpb.NewStringValue("sensitive-full-name"),
							"email":     structpb.NewStringValue("sensitive-email"),
							"token_claims": structpb.NewStructValue(&structpb.Struct{
								Fields: map[string]*structpb.Value{
									"iss":       structpb.NewStringValue("public-issuer"),
									"sub":       structpb.NewStringValue("sensitive-subject"),
									"aud":       structpb.NewStringValue("sensitive-audience"),
									"exp":       structpb.NewNumberValue(float64(now.Unix())),
									"iat":       structpb.NewNumberValue(float64(now.Unix())),
									"auth_time": structpb.NewNumberValue(float64(now.Unix())),
									"nonce":     structpb.NewStringValue("secret-nonce"),
									"acr":       structpb.NewStringValue("public-acr"),
									"amr": structpb.NewListValue(&structpb.ListValue{Values: []*structpb.Value{
										structpb.NewStringValue("public-amr-1"),
										structpb.NewStringValue("public-amr-2"),
									}}),
									"azp":                   structpb.NewStringValue("public-azp-1"),
									"name":                  structpb.NewStringValue("sensitive-name"),
									"given_name":            structpb.NewStringValue("sensitive-given-name"),
									"family_name":           structpb.NewStringValue("sensitive-family-name"),
									"middle_name":           structpb.NewStringValue("sensitive-middle-name"),
									"nickname":              structpb.NewStringValue("sensitive-nickname"),
									"preferred_username":    structpb.NewStringValue("sensitive-preferred-username"),
									"profile":               structpb.NewStringValue("sensitive-profile"),
									"picture":               structpb.NewStringValue("sensitive-picture"),
									"website":               structpb.NewStringValue("sensitive-website"),
									"email":                 structpb.NewStringValue("sensitive-email"),
									"email_verified":        structpb.NewBoolValue(true),
									"gender":                structpb.NewStringValue("sensitive-gender"),
									"birthdate":             structpb.NewStringValue("sensitive-birthdate"),
									"zoneinfo":              structpb.NewStringValue("public-zoneinfo"),
									"locale":                structpb.NewStringValue("public-locale"),
									"phone_number":          structpb.NewStringValue("sensitive-phone-number"),
									"phone_number_verified": structpb.NewBoolValue(false),
									"updated_at":            structpb.NewNumberValue(float64(now.Unix())),
									"address": structpb.NewStructValue(&structpb.Struct{
										Fields: map[string]*structpb.Value{
											"formatted":      structpb.NewStringValue("sensitive-formatted"),
											"street_address": structpb.NewStringValue("sensitive-street-address"),
											"locality":       structpb.NewStringValue("sensitive-locality"),
											"region":         structpb.NewStringValue("sensitive-region"),
											"postal_code":    structpb.NewStringValue("sensitive-postal-code"),
											"country":        structpb.NewStringValue("sensitive-country"),
										},
									}),
								},
							}),
							"userinfo_claims": structpb.NewStructValue(&structpb.Struct{
								Fields: map[string]*structpb.Value{
									"name":                  structpb.NewStringValue("sensitive-name"),
									"given_name":            structpb.NewStringValue("sensitive-given-name"),
									"family_name":           structpb.NewStringValue("sensitive-family-name"),
									"middle_name":           structpb.NewStringValue("sensitive-middle-name"),
									"nickname":              structpb.NewStringValue("sensitive-nickname"),
									"preferred_username":    structpb.NewStringValue("sensitive-preferred-username"),
									"profile":               structpb.NewStringValue("sensitive-profile"),
									"picture":               structpb.NewStringValue("sensitive-picture"),
									"website":               structpb.NewStringValue("sensitive-website"),
									"email":                 structpb.NewStringValue("sensitive-email"),
									"email_verified":        structpb.NewBoolValue(true),
									"gender":                structpb.NewStringValue("sensitive-gender"),
									"birthdate":             structpb.NewStringValue("sensitive-birthdate"),
									"zoneinfo":              structpb.NewStringValue("public-zoneinfo"),
									"locale":                structpb.NewStringValue("public-locale"),
									"phone_number":          structpb.NewStringValue("sensitive-phone-number"),
									"phone_number_verified": structpb.NewBoolValue(false),
									"updated_at":            structpb.NewNumberValue(float64(now.Unix())),
									"address": structpb.NewStructValue(&structpb.Struct{
										Fields: map[string]*structpb.Value{
											"formatted":      structpb.NewStringValue("sensitive-formatted"),
											"street_address": structpb.NewStringValue("sensitive-street-address"),
											"locality":       structpb.NewStringValue("sensitive-locality"),
											"region":         structpb.NewStringValue("sensitive-region"),
											"postal_code":    structpb.NewStringValue("sensitive-postal-code"),
											"country":        structpb.NewStringValue("sensitive-country"),
										},
									}),
								},
							}),
						},
					},
					ManagedGroupIds:   []string{"public-managed-group-id-1", "public-managed-group-id-2"},
					AuthorizedActions: []string{"public-authorized-actions-1", "public-authorized-actions-2"},
				},
			},
			wantEvent: &eventlogger.Event{
				Type:      "test",
				CreatedAt: now,
				Payload: &Account{
					Id: "public-acc-id",
					Scope: &scopes.ScopeInfo{
						Id:            "public-scope-id",
						Type:          "public-scope-type",
						Name:          "public-scope-name",
						Description:   "public-scope-description",
						ParentScopeId: "public-parent-scopeid",
					},
					Name:         wrapperspb.String("public-name"),
					Description:  wrapperspb.String("public-description"),
					CreatedTime:  timestamppb.New(now),
					UpdatedTime:  timestamppb.New(now),
					Version:      1,
					Type:         "oidc",
					AuthMethodId: "public-auth-method-id",
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"issuer":    structpb.NewStringValue("public-issuer"),
							"subject":   structpb.NewStringValue(encrypt.RedactedData),
							"full_name": structpb.NewStringValue(encrypt.RedactedData),
							"email":     structpb.NewStringValue(encrypt.RedactedData),
							"token_claims": structpb.NewStructValue(&structpb.Struct{
								Fields: map[string]*structpb.Value{
									"iss":       structpb.NewStringValue("public-issuer"),
									"sub":       structpb.NewStringValue(encrypt.RedactedData),
									"aud":       structpb.NewStringValue(encrypt.RedactedData),
									"exp":       structpb.NewNumberValue(float64(now.Unix())),
									"iat":       structpb.NewNumberValue(float64(now.Unix())),
									"auth_time": structpb.NewNumberValue(float64(now.Unix())),
									"nonce":     structpb.NewStringValue(encrypt.RedactedData),
									"acr":       structpb.NewStringValue("public-acr"),
									"amr": structpb.NewListValue(&structpb.ListValue{Values: []*structpb.Value{
										structpb.NewStringValue("public-amr-1"),
										structpb.NewStringValue("public-amr-2"),
									}}),
									"azp":                   structpb.NewStringValue("public-azp-1"),
									"name":                  structpb.NewStringValue(encrypt.RedactedData),
									"given_name":            structpb.NewStringValue(encrypt.RedactedData),
									"family_name":           structpb.NewStringValue(encrypt.RedactedData),
									"middle_name":           structpb.NewStringValue(encrypt.RedactedData),
									"nickname":              structpb.NewStringValue(encrypt.RedactedData),
									"preferred_username":    structpb.NewStringValue(encrypt.RedactedData),
									"profile":               structpb.NewStringValue(encrypt.RedactedData),
									"picture":               structpb.NewStringValue(encrypt.RedactedData),
									"website":               structpb.NewStringValue(encrypt.RedactedData),
									"email":                 structpb.NewStringValue(encrypt.RedactedData),
									"email_verified":        structpb.NewBoolValue(true),
									"gender":                structpb.NewStringValue(encrypt.RedactedData),
									"birthdate":             structpb.NewStringValue(encrypt.RedactedData),
									"zoneinfo":              structpb.NewStringValue("public-zoneinfo"),
									"locale":                structpb.NewStringValue("public-locale"),
									"phone_number":          structpb.NewStringValue(encrypt.RedactedData),
									"phone_number_verified": structpb.NewBoolValue(false),
									"updated_at":            structpb.NewNumberValue(float64(now.Unix())),
									"address":               structpb.NewStringValue(encrypt.RedactedData),
								},
							}),
							"userinfo_claims": structpb.NewStructValue(&structpb.Struct{
								Fields: map[string]*structpb.Value{
									"name":                  structpb.NewStringValue(encrypt.RedactedData),
									"given_name":            structpb.NewStringValue(encrypt.RedactedData),
									"family_name":           structpb.NewStringValue(encrypt.RedactedData),
									"middle_name":           structpb.NewStringValue(encrypt.RedactedData),
									"nickname":              structpb.NewStringValue(encrypt.RedactedData),
									"preferred_username":    structpb.NewStringValue(encrypt.RedactedData),
									"profile":               structpb.NewStringValue(encrypt.RedactedData),
									"picture":               structpb.NewStringValue(encrypt.RedactedData),
									"website":               structpb.NewStringValue(encrypt.RedactedData),
									"email":                 structpb.NewStringValue(encrypt.RedactedData),
									"email_verified":        structpb.NewBoolValue(true),
									"gender":                structpb.NewStringValue(encrypt.RedactedData),
									"birthdate":             structpb.NewStringValue(encrypt.RedactedData),
									"zoneinfo":              structpb.NewStringValue("public-zoneinfo"),
									"locale":                structpb.NewStringValue("public-locale"),
									"phone_number":          structpb.NewStringValue(encrypt.RedactedData),
									"phone_number_verified": structpb.NewBoolValue(false),
									"updated_at":            structpb.NewNumberValue(float64(now.Unix())),
									"address":               structpb.NewStringValue(encrypt.RedactedData),
								},
							}),
						},
					},
					ManagedGroupIds:   []string{"public-managed-group-id-1", "public-managed-group-id-2"},
					AuthorizedActions: []string{"public-authorized-actions-1", "public-authorized-actions-2"},
				},
			},
		},
	}

	testEncryptingFilter := api.NewEncryptFilter(t, wrapper.TestWrapper(t))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			got, err := testEncryptingFilter.Process(context.Background(), tt.testEvent)
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
