package accounts

import (
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/auth/oidc"
	"github.com/hashicorp/boundary/internal/auth/password"
	pb "github.com/hashicorp/boundary/internal/gen/controller/api/resources/accounts"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"google.golang.org/protobuf/types/known/structpb"
)

func fieldError(field, details string) string {
	return fmt.Sprintf(`{name: %q, desc: %q}`, field, details)
}

func TestValidateCreateRequest(t *testing.T) {
	cases := []struct {
		name        string
		item        *pb.Account
		errContains string
	}{
		{
			name: "unrecognized authmethod prefix",
			item: &pb.Account{
				AuthMethodId: "anything_1234567890",
			},
			errContains: fieldError(authMethodIdField, "Unknown auth method type from ID."),
		},
		{
			name: "oidc authmethod prefix",
			item: &pb.Account{
				AuthMethodId: oidc.AuthMethodPrefix + "_1234567890",
			},
			errContains: fieldError(authMethodIdField, "Unable to create accounts for this auth method type."),
		},
		{
			name: "mismatched authmethod type",
			item: &pb.Account{
				Type:         auth.OidcSubtype.String(),
				AuthMethodId: password.AuthMethodPrefix + "_1234567890",
			},
			errContains: fieldError(typeField, "Doesn't match the parent resource's type."),
		},
		{
			name: "missing login name for password type",
			item: &pb.Account{
				Type:         auth.PasswordSubtype.String(),
				AuthMethodId: password.AuthMethodPrefix + "_1234567890",
			},
			errContains: fieldError(loginNameKey, "This is a required field for this type."),
		},
		{
			name: "bad attributes",
			item: &pb.Account{
				Type:         auth.PasswordSubtype.String(),
				AuthMethodId: password.AuthMethodPrefix + "_1234567890",
				Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
					"test": structpb.NewStringValue("something"),
				}},
			},
			errContains: fieldError(attributesField, "Attribute fields do not match the expected format."),
		},
		{
			name: "no error",
			item: &pb.Account{
				Type:         auth.PasswordSubtype.String(),
				AuthMethodId: password.AuthMethodPrefix + "_1234567890",
				Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
					loginNameKey: structpb.NewStringValue("something"),
				}},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := &pbs.CreateAccountRequest{Item: tc.item}
			err := validateCreateRequest(req)
			if tc.errContains == "" {
				require.NoError(t, err)
				return
			}
			assert.True(t, strings.Contains(err.Error(), tc.errContains),
				"%q wasn't contained in %q", tc.errContains, err.Error())
		})
	}
}

func TestValidateUpdateRequest(t *testing.T) {
	cases := []struct {
		name        string
		req         *pbs.UpdateAccountRequest
		errContains string
	}{
		{
			name: "password to oidc change type",
			req: &pbs.UpdateAccountRequest{
				Id: password.AccountPrefix + "_1234567890",
				Item: &pb.Account{
					Type: auth.OidcSubtype.String(),
				},
			},
			errContains: fieldError(typeField, "Cannot modify the resource type."),
		},
		{
			name: "oidc to password change type",
			req: &pbs.UpdateAccountRequest{
				Id: oidc.AccountPrefix + "_1234567890",
				Item: &pb.Account{
					Type: auth.PasswordSubtype.String(),
				},
			},
			errContains: fieldError(typeField, "Cannot modify the resource type."),
		},
		{
			name: "password bad attributes",
			req: &pbs.UpdateAccountRequest{
				Id: password.AccountPrefix + "_1234567890",
				Item: &pb.Account{
					Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
						"test": structpb.NewStringValue("something"),
					}},
				},
			},
			errContains: fieldError(attributesField, "Attribute fields do not match the expected format."),
		},
		{
			name: "oidc bad attributes",
			req: &pbs.UpdateAccountRequest{
				Id: oidc.AccountPrefix + "_1234567890",
				Item: &pb.Account{
					Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
						"test": structpb.NewStringValue("something"),
					}},
				},
			},
			errContains: fieldError(attributesField, "Attribute fields do not match the expected format."),
		},
		{
			name: "no error",
			req: &pbs.UpdateAccountRequest{
				Id:         oidc.AccountPrefix + "_1234567890",
				UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{}},
				Item: &pb.Account{
					Version: 1,
				},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateUpdateRequest(tc.req)
			if tc.errContains == "" {
				require.NoError(t, err)
				return
			}
			assert.True(t, strings.Contains(err.Error(), tc.errContains),
				"%q wasn't contained in %q", tc.errContains, err.Error())
		})
	}

	t.Run("oidc read only fields", func(t *testing.T) {
		readOnlyFields := []string{
			issuerIdField,
			subjectIdField,
			emailClaimField,
			nameClaimField,
		}
		err := validateUpdateRequest(&pbs.UpdateAccountRequest{
			Id:         oidc.AccountPrefix + "1234567890",
			UpdateMask: &fieldmaskpb.FieldMask{Paths: readOnlyFields},
		})

		for _, f := range readOnlyFields {
			expected := fieldError(f, "Field is read only.")
			assert.True(t, strings.Contains(err.Error(), expected),
				"%q wasn't contained in %q", expected, err.Error())
		}
	})
}
