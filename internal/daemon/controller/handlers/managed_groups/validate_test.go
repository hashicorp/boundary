package managed_groups

import (
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/auth/oidc"
	"github.com/hashicorp/boundary/internal/auth/password"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/intglobals"
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
				AuthMethodId: oidc.AuthMethodPrefix + "_1234567890",
			},
			errContains: fieldError(globals.TypeField, "Doesn't match the parent resource's type."),
		},
		{
			name: "missing oidc attributes",
			item: &pb.ManagedGroup{
				Type:         oidc.Subtype.String(),
				AuthMethodId: oidc.AuthMethodPrefix + "_1234567890",
				Attrs:        nil,
			},
			errContains: fieldError(globals.AttributesField, "Attribute fields is required."),
		},
		{
			name: "bad oidc attributes",
			item: &pb.ManagedGroup{
				Type:         oidc.Subtype.String(),
				AuthMethodId: oidc.AuthMethodPrefix + "_1234567890",
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
				AuthMethodId: oidc.AuthMethodPrefix + "_1234567890",
				Attrs: &pb.ManagedGroup_OidcManagedGroupAttributes{
					OidcManagedGroupAttributes: &pb.OidcManagedGroupAttributes{
						Filter: `"/foo/bar" == "zipzap"`,
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
	t.Parallel()
	cases := []struct {
		name        string
		req         *pbs.UpdateManagedGroupRequest
		errContains string
	}{
		{
			name: "oidc to password change type",
			req: &pbs.UpdateManagedGroupRequest{
				Id: intglobals.OidcManagedGroupPrefix + "_1234567890",
				Item: &pb.ManagedGroup{
					Type: password.Subtype.String(),
				},
			},
			errContains: fieldError(globals.TypeField, "Cannot modify the resource type."),
		},
		{
			name: "no error",
			req: &pbs.UpdateManagedGroupRequest{
				Id:         intglobals.OidcManagedGroupPrefix + "_1234567890",
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
	}
	for _, tc := range cases {
		tc := tc // capture range variable
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := validateUpdateRequest(tc.req)
			if tc.errContains == "" {
				require.NoError(t, err)
				return
			}
			assert.True(t, strings.Contains(err.Error(), tc.errContains),
				"%q wasn't contained in %q", tc.errContains, err.Error())
		})
	}
}
