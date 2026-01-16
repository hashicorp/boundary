// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package accounts

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/auth/ldap"
	"github.com/hashicorp/boundary/internal/auth/oidc"
	"github.com/hashicorp/boundary/internal/auth/password"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/accounts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
)

func fieldError(field, details string) string {
	return fmt.Sprintf(`{name: %q, desc: %q}`, field, details)
}

func TestValidateCreateRequest(t *testing.T) {
	t.Parallel()
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
			name: "mismatched pw authmethod oidc type",
			item: &pb.Account{
				Type:         oidc.Subtype.String(),
				AuthMethodId: globals.PasswordAuthMethodPrefix + "_1234567890",
			},
			errContains: fieldError(typeField, "Doesn't match the parent resource's type."),
		},
		{
			name: "mismatched oidc authmethod pw type",
			item: &pb.Account{
				Type:         password.Subtype.String(),
				AuthMethodId: globals.OidcAuthMethodPrefix + "_1234567890",
			},
			errContains: fieldError(typeField, "Doesn't match the parent resource's type."),
		},
		{
			name: "mismatched pw authmethod ldap type",
			item: &pb.Account{
				Type:         ldap.Subtype.String(),
				AuthMethodId: globals.PasswordAuthMethodPrefix + "_1234567890",
			},
			errContains: fieldError(typeField, "Doesn't match the parent resource's type."),
		},
		{
			name: "missing oidc attributes",
			item: &pb.Account{
				Type:         oidc.Subtype.String(),
				AuthMethodId: globals.OidcAuthMethodPrefix + "_1234567890",
			},
			errContains: fieldError(attributesField, "This is a required field."),
		},
		{
			name: "missing oidc subject",
			item: &pb.Account{
				Type:         oidc.Subtype.String(),
				AuthMethodId: globals.OidcAuthMethodPrefix + "_1234567890",
				Attrs: &pb.Account_OidcAccountAttributes{
					OidcAccountAttributes: &pb.OidcAccountAttributes{},
				},
			},
			errContains: fieldError(subjectField, "This is a required field for this type."),
		},
		{
			name: "read only name claim field",
			item: &pb.Account{
				Type:         oidc.Subtype.String(),
				AuthMethodId: globals.OidcAuthMethodPrefix + "_1234567890",
				Attrs: &pb.Account_OidcAccountAttributes{
					OidcAccountAttributes: &pb.OidcAccountAttributes{FullName: "something"},
				},
			},
			errContains: fieldError(nameClaimField, "This is a read only field."),
		},
		{
			name: "read only email claim field",
			item: &pb.Account{
				Type:         oidc.Subtype.String(),
				AuthMethodId: globals.OidcAuthMethodPrefix + "_1234567890",
				Attrs: &pb.Account_OidcAccountAttributes{
					OidcAccountAttributes: &pb.OidcAccountAttributes{Email: "something"},
				},
			},
			errContains: fieldError(emailClaimField, "This is a read only field."),
		},
		{
			name: "missing ldap attributes",
			item: &pb.Account{
				Type:         ldap.Subtype.String(),
				AuthMethodId: globals.LdapAuthMethodPrefix + "_1234567890",
			},
			errContains: fieldError(attributesField, "This is a required field."),
		},
		{
			name: "missing login name for ldap type",
			item: &pb.Account{
				Type:         ldap.Subtype.String(),
				AuthMethodId: globals.LdapAuthMethodPrefix + "_1234567890",
				Attrs: &pb.Account_LdapAccountAttributes{
					LdapAccountAttributes: &pb.LdapAccountAttributes{},
				},
			},
			errContains: fieldError(loginAttrField, "This is a required field for this type."),
		},
		{
			name: "read only full name attr field",
			item: &pb.Account{
				Type:         ldap.Subtype.String(),
				AuthMethodId: globals.LdapAuthMethodPrefix + "_1234567890",
				Attrs: &pb.Account_LdapAccountAttributes{
					LdapAccountAttributes: &pb.LdapAccountAttributes{FullName: "something"},
				},
			},
			errContains: fieldError(nameAttrField, "This is a read only field."),
		},
		{
			name: "read only email attr field",
			item: &pb.Account{
				Type:         ldap.Subtype.String(),
				AuthMethodId: globals.LdapAuthMethodPrefix + "_1234567890",
				Attrs: &pb.Account_LdapAccountAttributes{
					LdapAccountAttributes: &pb.LdapAccountAttributes{Email: "something"},
				},
			},
			errContains: fieldError(emailAttrField, "This is a read only field."),
		},
		{
			name: "read only dn attr field",
			item: &pb.Account{
				Type:         ldap.Subtype.String(),
				AuthMethodId: globals.LdapAuthMethodPrefix + "_1234567890",
				Attrs: &pb.Account_LdapAccountAttributes{
					LdapAccountAttributes: &pb.LdapAccountAttributes{Dn: "something"},
				},
			},
			errContains: fieldError(dnAttrField, "This is a read only field."),
		},
		{
			name: "read only member of attr field",
			item: &pb.Account{
				Type:         ldap.Subtype.String(),
				AuthMethodId: globals.LdapAuthMethodPrefix + "_1234567890",
				Attrs: &pb.Account_LdapAccountAttributes{
					LdapAccountAttributes: &pb.LdapAccountAttributes{MemberOfGroups: []string{"something"}},
				},
			},
			errContains: fieldError(memberOfAttrField, "This is a read only field."),
		},
		{
			name: "missing password attributes",
			item: &pb.Account{
				Type:         password.Subtype.String(),
				AuthMethodId: globals.PasswordAuthMethodPrefix + "_1234567890",
			},
			errContains: fieldError(attributesField, "This is a required field."),
		},
		{
			name: "missing login name for password type",
			item: &pb.Account{
				Type:         password.Subtype.String(),
				AuthMethodId: globals.PasswordAuthMethodPrefix + "_1234567890",
				Attrs: &pb.Account_PasswordAccountAttributes{
					PasswordAccountAttributes: &pb.PasswordAccountAttributes{},
				},
			},
			errContains: fieldError(loginNameKey, "This is a required field for this type."),
		},
		{
			name: "no error",
			item: &pb.Account{
				Type:         password.Subtype.String(),
				AuthMethodId: globals.PasswordAuthMethodPrefix + "_1234567890",
				Attrs: &pb.Account_PasswordAccountAttributes{
					PasswordAccountAttributes: &pb.PasswordAccountAttributes{
						LoginName: "something",
					},
				},
			},
		},
		{
			name: "no oidc errors",
			item: &pb.Account{
				Type:         oidc.Subtype.String(),
				AuthMethodId: globals.OidcAuthMethodPrefix + "_1234567890",
				Attrs: &pb.Account_OidcAccountAttributes{
					OidcAccountAttributes: &pb.OidcAccountAttributes{Subject: "no oidc errors"},
				},
			},
		},
		{
			name: "no ldap errors",
			item: &pb.Account{
				Type:         ldap.Subtype.String(),
				AuthMethodId: globals.LdapAuthMethodPrefix + "_1234567890",
				Attrs: &pb.Account_LdapAccountAttributes{
					LdapAccountAttributes: &pb.LdapAccountAttributes{LoginName: "no oidc errors"},
				},
			},
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			req := &pbs.CreateAccountRequest{Item: tc.item}
			err := validateCreateRequest(context.Background(), req)
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
	t.Parallel()
	cases := []struct {
		name        string
		req         *pbs.UpdateAccountRequest
		errContains string
	}{
		{
			name: "password to oidc change type, old prefix",
			req: &pbs.UpdateAccountRequest{
				Id: globals.PasswordAccountPreviousPrefix + "_1234567890",
				Item: &pb.Account{
					Type: oidc.Subtype.String(),
				},
			},
			errContains: fieldError(typeField, "Cannot modify the resource type."),
		},
		{
			name: "password to oidc change type, new prefix",
			req: &pbs.UpdateAccountRequest{
				Id: globals.PasswordAccountPrefix + "_1234567890",
				Item: &pb.Account{
					Type: oidc.Subtype.String(),
				},
			},
			errContains: fieldError(typeField, "Cannot modify the resource type."),
		},
		{
			name: "oidc to password change type",
			req: &pbs.UpdateAccountRequest{
				Id: globals.OidcAccountPrefix + "_1234567890",
				Item: &pb.Account{
					Type: password.Subtype.String(),
				},
			},
			errContains: fieldError(typeField, "Cannot modify the resource type."),
		},
		{
			name: "no error",
			req: &pbs.UpdateAccountRequest{
				Id:         globals.OidcAccountPrefix + "_1234567890",
				UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{}},
				Item: &pb.Account{
					Version: 1,
				},
			},
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := validateUpdateRequest(context.Background(), tc.req)
			if tc.errContains == "" {
				require.NoError(t, err)
				return
			}
			assert.True(t, strings.Contains(err.Error(), tc.errContains),
				"%q wasn't contained in %q", tc.errContains, err.Error())
		})
	}

	t.Run("oidc read only fields", func(t *testing.T) {
		t.Parallel()
		readOnlyFields := []string{
			emailClaimField,
			nameClaimField,
		}
		err := validateUpdateRequest(context.Background(), &pbs.UpdateAccountRequest{
			Id:         globals.OidcAccountPrefix + "_1234567890",
			UpdateMask: &fieldmaskpb.FieldMask{Paths: readOnlyFields},
		})

		for _, f := range readOnlyFields {
			expected := fieldError(f, "Field is read only.")
			assert.True(t, strings.Contains(err.Error(), expected),
				"%q wasn't contained in %q", expected, err.Error())
		}
	})

	t.Run("oidc write only at create fields", func(t *testing.T) {
		t.Parallel()
		readOnlyFields := []string{
			issuerField,
			subjectField,
		}
		err := validateUpdateRequest(context.Background(), &pbs.UpdateAccountRequest{
			Id:         globals.OidcAccountPrefix + "_1234567890",
			UpdateMask: &fieldmaskpb.FieldMask{Paths: readOnlyFields},
		})

		for _, f := range readOnlyFields {
			expected := fieldError(f, "Field cannot be updated.")
			assert.True(t, strings.Contains(err.Error(), expected),
				"%q wasn't contained in %q", expected, err.Error())
		}
	})
}
