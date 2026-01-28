// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package authmethods

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/authmethods"
	pba "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/authtokens"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestTransformAuthenticateRequestAttributes(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		input    *pbs.AuthenticateRequest
		expected *pbs.AuthenticateRequest
	}{
		{
			name:     "empty-request",
			input:    &pbs.AuthenticateRequest{},
			expected: &pbs.AuthenticateRequest{},
		},
		{
			name: "password-attributes",
			input: &pbs.AuthenticateRequest{
				AuthMethodId: "apw_test",
				Attrs: &pbs.AuthenticateRequest_Attributes{
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"login_name": structpb.NewStringValue("login-name"),
							"password":   structpb.NewStringValue("password"),
						},
					},
				},
			},
			expected: &pbs.AuthenticateRequest{
				AuthMethodId: "apw_test",
				Attrs: &pbs.AuthenticateRequest_PasswordLoginAttributes{
					PasswordLoginAttributes: &pbs.PasswordLoginAttributes{
						LoginName: "login-name",
						Password:  "password",
					},
				},
			},
		},
		{
			name: "ldap-attributes",
			input: &pbs.AuthenticateRequest{
				AuthMethodId: "amldap_test",
				Attrs: &pbs.AuthenticateRequest_Attributes{
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"login_name": structpb.NewStringValue("login-name"),
							"password":   structpb.NewStringValue("password"),
						},
					},
				},
			},
			expected: &pbs.AuthenticateRequest{
				AuthMethodId: "amldap_test",
				Attrs: &pbs.AuthenticateRequest_LdapLoginAttributes{
					LdapLoginAttributes: &pbs.LdapLoginAttributes{
						LoginName: "login-name",
						Password:  "password",
					},
				},
			},
		},
		{
			name: "oidc-start-attributes",
			input: &pbs.AuthenticateRequest{
				AuthMethodId: "amoidc_test",
				Command:      "start",
				Attrs: &pbs.AuthenticateRequest_Attributes{
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"roundtrip_payload": structpb.NewStructValue(&structpb.Struct{
								Fields: map[string]*structpb.Value{
									"field1": structpb.NewBoolValue(true),
									"field2": structpb.NewStringValue("value2"),
								},
							}),
							"cached_roundtrip_payload": structpb.NewStringValue("cached-roundtrip-payload"),
						},
					},
				},
			},
			expected: &pbs.AuthenticateRequest{
				AuthMethodId: "amoidc_test",
				Command:      "start",
				Attrs: &pbs.AuthenticateRequest_OidcStartAttributes{
					OidcStartAttributes: &pbs.OidcStartAttributes{
						RoundtripPayload: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								"field1": structpb.NewBoolValue(true),
								"field2": structpb.NewStringValue("value2"),
							},
						},
						CachedRoundtripPayload: "cached-roundtrip-payload",
					},
				},
			},
		},
		{
			name: "oidc-callback-attributes",
			input: &pbs.AuthenticateRequest{
				AuthMethodId: "amoidc_test",
				Command:      "callback",
				Attrs: &pbs.AuthenticateRequest_Attributes{
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"code":              structpb.NewStringValue("code"),
							"state":             structpb.NewStringValue("state"),
							"error":             structpb.NewStringValue("error"),
							"error_description": structpb.NewStringValue("error-description"),
							"error_uri":         structpb.NewStringValue("error-uri"),
						},
					},
				},
			},
			expected: &pbs.AuthenticateRequest{
				AuthMethodId: "amoidc_test",
				Command:      "callback",
				Attrs: &pbs.AuthenticateRequest_OidcAuthMethodAuthenticateCallbackRequest{
					OidcAuthMethodAuthenticateCallbackRequest: &pb.OidcAuthMethodAuthenticateCallbackRequest{
						Code:             "code",
						State:            "state",
						Error:            "error",
						ErrorDescription: "error-description",
						ErrorUri:         "error-uri",
					},
				},
			},
		},
		{
			name: "oidc-callback-attributes-with-extra-fields",
			input: &pbs.AuthenticateRequest{
				AuthMethodId: "amoidc_test",
				Command:      "callback",
				Attrs: &pbs.AuthenticateRequest_Attributes{
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"code":               structpb.NewStringValue("code"),
							"state":              structpb.NewStringValue("state"),
							"non-callback-field": structpb.NewBoolValue(true),
						},
					},
				},
			},
			expected: &pbs.AuthenticateRequest{
				AuthMethodId: "amoidc_test",
				Command:      "callback",
				Attrs: &pbs.AuthenticateRequest_OidcAuthMethodAuthenticateCallbackRequest{
					OidcAuthMethodAuthenticateCallbackRequest: &pb.OidcAuthMethodAuthenticateCallbackRequest{
						Code:  "code",
						State: "state",
					},
				},
			},
		},
		{
			name: "oidc-token-attributes",
			input: &pbs.AuthenticateRequest{
				AuthMethodId: "amoidc_test",
				Command:      "token",
				Attrs: &pbs.AuthenticateRequest_Attributes{
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"token_id": structpb.NewStringValue("token-id"),
						},
					},
				},
			},
			expected: &pbs.AuthenticateRequest{
				AuthMethodId: "amoidc_test",
				Command:      "token",
				Attrs: &pbs.AuthenticateRequest_OidcAuthMethodAuthenticateTokenRequest{
					OidcAuthMethodAuthenticateTokenRequest: &pb.OidcAuthMethodAuthenticateTokenRequest{
						TokenId: "token-id",
					},
				},
			},
		},
	}

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			in := proto.Clone(c.input)
			require.NoError(t, transformAuthenticateRequestAttributes(context.Background(), in))
			require.Empty(t, cmp.Diff(c.expected, in, protocmp.Transform()))
		})
	}
}

func TestTransformAuthenticateRequestAttributesErrors(t *testing.T) {
	t.Parallel()
	t.Run("not-an-authenticate-request", func(t *testing.T) {
		t.Parallel()
		require.Error(t, transformAuthenticateRequestAttributes(context.Background(), &pb.AuthMethod{}))
	})
	t.Run("invalid-auth-method-id", func(t *testing.T) {
		t.Parallel()
		require.Error(t, transformAuthenticateRequestAttributes(context.Background(), &pbs.AuthenticateRequest{
			AuthMethodId: "invalid",
			Attrs: &pbs.AuthenticateRequest_Attributes{
				Attributes: &structpb.Struct{},
			},
		}))
	})
	t.Run("invalid-oidc-command", func(t *testing.T) {
		t.Parallel()
		require.Error(t, transformAuthenticateRequestAttributes(context.Background(), &pbs.AuthenticateRequest{
			AuthMethodId: "amoidc_test",
			Command:      "invalid",
			Attrs: &pbs.AuthenticateRequest_Attributes{
				Attributes: &structpb.Struct{},
			},
		}))
	})
	t.Run("invalid-password-attributes", func(t *testing.T) {
		t.Parallel()
		require.Error(t, transformAuthenticateRequestAttributes(context.Background(), &pbs.AuthenticateRequest{
			AuthMethodId: "apw_test",
			Attrs: &pbs.AuthenticateRequest_Attributes{
				Attributes: &structpb.Struct{
					Fields: map[string]*structpb.Value{
						"field1": structpb.NewBoolValue(true),
						"field2": structpb.NewStringValue("value2"),
					},
				},
			},
		}))
	})
	t.Run("invalid-ldap-attributes", func(t *testing.T) {
		t.Parallel()
		require.Error(t, transformAuthenticateRequestAttributes(context.Background(), &pbs.AuthenticateRequest{
			AuthMethodId: "amldap_test",
			Attrs: &pbs.AuthenticateRequest_Attributes{
				Attributes: &structpb.Struct{
					Fields: map[string]*structpb.Value{
						"field1": structpb.NewBoolValue(true),
						"field2": structpb.NewStringValue("value2"),
					},
				},
			},
		}))
	})
	t.Run("invalid-oidc-start-attributes", func(t *testing.T) {
		t.Parallel()
		require.Error(t, transformAuthenticateRequestAttributes(context.Background(), &pbs.AuthenticateRequest{
			AuthMethodId: "amoidc_test",
			Command:      "start",
			Attrs: &pbs.AuthenticateRequest_Attributes{
				Attributes: &structpb.Struct{
					Fields: map[string]*structpb.Value{
						"field1": structpb.NewBoolValue(true),
						"field2": structpb.NewStringValue("value2"),
					},
				},
			},
		}))
	})
	t.Run("invalid-oidc-token-attributes", func(t *testing.T) {
		t.Parallel()
		require.Error(t, transformAuthenticateRequestAttributes(context.Background(), &pbs.AuthenticateRequest{
			AuthMethodId: "amoidc_test",
			Command:      "token",
			Attrs: &pbs.AuthenticateRequest_Attributes{
				Attributes: &structpb.Struct{
					Fields: map[string]*structpb.Value{
						"field1": structpb.NewBoolValue(true),
						"field2": structpb.NewStringValue("value2"),
					},
				},
			},
		}))
	})
}

func TestTransformAuthenticateResponseAttributes(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		input    *pbs.AuthenticateResponse
		expected *pbs.AuthenticateResponse
	}{
		{
			name: "empty-attributes",
			input: &pbs.AuthenticateResponse{
				Command: "testcommand",
			},
			expected: &pbs.AuthenticateResponse{
				Command: "testcommand",
			},
		},
		{
			name: "unstructured-attributes",
			input: &pbs.AuthenticateResponse{
				Command: "testcommand",
				Attrs: &pbs.AuthenticateResponse_Attributes{
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"field1": structpb.NewBoolValue(true),
							"field2": structpb.NewStringValue("value2"),
						},
					},
				},
			},
			expected: &pbs.AuthenticateResponse{
				Command: "testcommand",
				Attrs: &pbs.AuthenticateResponse_Attributes{
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"field1": structpb.NewBoolValue(true),
							"field2": structpb.NewStringValue("value2"),
						},
					},
				},
			},
		},
		{
			name: "authtoken-attributes",
			input: &pbs.AuthenticateResponse{
				Command: "testcommand",
				Attrs: &pbs.AuthenticateResponse_AuthTokenResponse{
					AuthTokenResponse: &pba.AuthToken{
						Id: "token-id",
					},
				},
			},
			expected: &pbs.AuthenticateResponse{
				Command: "testcommand",
				Attrs: &pbs.AuthenticateResponse_Attributes{
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"id": structpb.NewStringValue("token-id"),
						},
					},
				},
			},
		},
		{
			name: "oidc-start-attributes",
			input: &pbs.AuthenticateResponse{
				Command: "testcommand",
				Attrs: &pbs.AuthenticateResponse_OidcAuthMethodAuthenticateStartResponse{
					OidcAuthMethodAuthenticateStartResponse: &pb.OidcAuthMethodAuthenticateStartResponse{
						AuthUrl: "auth-url",
						TokenId: "token-id",
					},
				},
			},
			expected: &pbs.AuthenticateResponse{
				Command: "testcommand",
				Attrs: &pbs.AuthenticateResponse_Attributes{
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"auth_url": structpb.NewStringValue("auth-url"),
							"token_id": structpb.NewStringValue("token-id"),
						},
					},
				},
			},
		},
		{
			name: "oidc-callback-attributes",
			input: &pbs.AuthenticateResponse{
				Command: "testcommand",
				Attrs: &pbs.AuthenticateResponse_OidcAuthMethodAuthenticateCallbackResponse{
					OidcAuthMethodAuthenticateCallbackResponse: &pb.OidcAuthMethodAuthenticateCallbackResponse{
						FinalRedirectUrl: "final-redirect-url",
					},
				},
			},
			expected: &pbs.AuthenticateResponse{
				Command: "testcommand",
				Attrs: &pbs.AuthenticateResponse_Attributes{
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"final_redirect_url": structpb.NewStringValue("final-redirect-url"),
						},
					},
				},
			},
		},
		{
			name: "oidc-token-attributes",
			input: &pbs.AuthenticateResponse{
				Command: "testcommand",
				Attrs: &pbs.AuthenticateResponse_OidcAuthMethodAuthenticateTokenResponse{
					OidcAuthMethodAuthenticateTokenResponse: &pb.OidcAuthMethodAuthenticateTokenResponse{
						Status: "status",
					},
				},
			},
			expected: &pbs.AuthenticateResponse{
				Command: "testcommand",
				Attrs: &pbs.AuthenticateResponse_Attributes{
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"status": structpb.NewStringValue("status"),
						},
					},
				},
			},
		},
	}

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			in := proto.Clone(c.input)
			require.NoError(t, transformAuthenticateResponseAttributes(context.Background(), in))
			require.Empty(t, cmp.Diff(c.expected, in, protocmp.Transform()))
		})
	}
}

func TestTransformAuthenticateResponseAttributesErrors(t *testing.T) {
	t.Parallel()
	t.Run("not-an-authenticate-response", func(t *testing.T) {
		t.Parallel()
		require.Error(t, transformAuthenticateResponseAttributes(context.Background(), &pb.AuthMethod{}))
	})
}
