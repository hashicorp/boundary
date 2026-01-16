// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package managed_groups

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
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/managedgroups"
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
		item        *pb.ManagedGroup
		errContains string
	}{
		{
			name: "unrecognized authmethod prefix",
			item: &pb.ManagedGroup{
				AuthMethodId: "anything_1234567890",
			},
			errContains: fieldError(globals.AuthMethodIdField, "Unknown auth method type from ID."),
		},
		{
			name: "mismatched oidc authmethod pw type",
			item: &pb.ManagedGroup{
				Type:         "ldap",
				AuthMethodId: globals.OidcAuthMethodPrefix + "_1234567890",
			},
			errContains: fieldError(globals.TypeField, "Doesn't match the parent resource's type."),
		},
		{
			name: "missing oidc attributes",
			item: &pb.ManagedGroup{
				Type:         oidc.Subtype.String(),
				AuthMethodId: globals.OidcAuthMethodPrefix + "_1234567890",
				Attrs:        nil,
			},
			errContains: fieldError(globals.AttributesField, "Attribute fields is required."),
		},
		{
			name: "bad oidc attributes",
			item: &pb.ManagedGroup{
				Type:         oidc.Subtype.String(),
				AuthMethodId: globals.OidcAuthMethodPrefix + "_1234567890",
				Attrs: &pb.ManagedGroup_OidcManagedGroupAttributes{
					OidcManagedGroupAttributes: &pb.OidcManagedGroupAttributes{
						Filter: "foobar",
					},
				},
			},
			errContains: "Error evaluating submitted filter",
		},
		{
			name: "no oidc errors",
			item: &pb.ManagedGroup{
				Type:         oidc.Subtype.String(),
				AuthMethodId: globals.OidcAuthMethodPrefix + "_1234567890",
				Attrs: &pb.ManagedGroup_OidcManagedGroupAttributes{
					OidcManagedGroupAttributes: &pb.OidcManagedGroupAttributes{
						Filter: `"/foo/bar" == "zipzap"`,
					},
				},
			},
		},
		{
			name: "mismatched ldap authmethod pw type",
			item: &pb.ManagedGroup{
				Type:         "oidc",
				AuthMethodId: globals.LdapAuthMethodPrefix + "_1234567890",
			},
			errContains: fieldError(globals.TypeField, "Doesn't match the parent resource's type."),
		},
		{
			name: "missing ldap attributes",
			item: &pb.ManagedGroup{
				Type:         ldap.Subtype.String(),
				AuthMethodId: globals.LdapAuthMethodPrefix + "_1234567890",
				Attrs:        nil,
			},
			errContains: fieldError(globals.AttributesField, "Attribute fields is required."),
		},
		{
			name: "bad ldap attributes",
			item: &pb.ManagedGroup{
				Type:         ldap.Subtype.String(),
				AuthMethodId: globals.LdapAuthMethodPrefix + "_1234567890",
				Attrs: &pb.ManagedGroup_LdapManagedGroupAttributes{
					LdapManagedGroupAttributes: &pb.LdapManagedGroupAttributes{
						GroupNames: []string{},
					},
				},
			},
			errContains: "name: \"attributes.group_names\", desc: \"This field is required.",
		},
		{
			name: "no ldap errors",
			item: &pb.ManagedGroup{
				Type:         ldap.Subtype.String(),
				AuthMethodId: globals.LdapAuthMethodPrefix + "_1234567890",
				Attrs: &pb.ManagedGroup_LdapManagedGroupAttributes{
					LdapManagedGroupAttributes: &pb.LdapManagedGroupAttributes{
						GroupNames: []string{"admin"},
					},
				},
			},
		},
	}
	for _, tc := range cases {
		tc := tc // capture range variable
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			req := &pbs.CreateManagedGroupRequest{Item: tc.item}
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
		req         *pbs.UpdateManagedGroupRequest
		errContains string
	}{
		{
			name: "oidc to password change type",
			req: &pbs.UpdateManagedGroupRequest{
				Id: globals.OidcManagedGroupPrefix + "_1234567890",
				Item: &pb.ManagedGroup{
					Type: password.Subtype.String(),
				},
			},
			errContains: fieldError(globals.TypeField, "Cannot modify the resource type."),
		},
		{
			name: "oidc no error",
			req: &pbs.UpdateManagedGroupRequest{
				Id:         globals.OidcManagedGroupPrefix + "_1234567890",
				UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{}},
				Item: &pb.ManagedGroup{
					Version: 1,
					Attrs: &pb.ManagedGroup_OidcManagedGroupAttributes{
						OidcManagedGroupAttributes: &pb.OidcManagedGroupAttributes{
							Filter: `"/foo/bar" == "zipzap"`,
						},
					},
				},
			},
		},
		{
			name: "ldap to password change type",
			req: &pbs.UpdateManagedGroupRequest{
				Id: globals.LdapManagedGroupPrefix + "_1234567890",
				Item: &pb.ManagedGroup{
					Type: password.Subtype.String(),
				},
			},
			errContains: fieldError(globals.TypeField, "Cannot modify the resource type."),
		},
		{
			name: "ldap no error",
			req: &pbs.UpdateManagedGroupRequest{
				Id:         globals.LdapManagedGroupPrefix + "_1234567890",
				UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{}},
				Item: &pb.ManagedGroup{
					Version: 1,
					Attrs: &pb.ManagedGroup_LdapManagedGroupAttributes{
						LdapManagedGroupAttributes: &pb.LdapManagedGroupAttributes{
							GroupNames: []string{"admin"},
						},
					},
				},
			},
		},
	}
	for _, tc := range cases {
		tc := tc // capture range variable
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
}
