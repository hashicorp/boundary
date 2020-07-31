package resource

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Resource(t *testing.T) {

	tests := []struct {
		typeString string
		want       Type
	}{
		{
			typeString: "unknown",
			want:       Unknown,
		},
		{
			typeString: "scope",
			want:       Scope,
		},
		{
			typeString: "user",
			want:       User,
		},
		{
			typeString: "group",
			want:       Group,
		},
		{
			typeString: "role",
			want:       Role,
		},
		{
			typeString: "org",
			want:       Org,
		},
		{
			typeString: "group-member",
			want:       GroupMember,
		},
		{
			typeString: "group-user-member",
			want:       GroupUserMember,
		},
		{
			typeString: "assigned-role",
			want:       AssignedRole,
		},
		{
			typeString: "assigned-user-role",
			want:       AssignedUserRole,
		},
		{
			typeString: "assigned-group-role",
			want:       AssignedGroupRole,
		},
		{
			typeString: "role-grant",
			want:       RoleGrant,
		},
		{
			typeString: "auth-method",
			want:       AuthMethod,
		},
		{
			typeString: "project",
			want:       Project,
		},
		{
			typeString: "*",
			want:       All,
		},
		{
			typeString: "host-catalog",
			want:       HostCatalog,
		},
		{
			typeString: "host-set",
			want:       HostSet,
		},
		{
			typeString: "host",
			want:       Host,
		},
		{
			typeString: "target",
			want:       Target,
		},
		{
			typeString: "global",
			want:       Global,
		},
	}
	for _, tt := range tests {
		t.Run(tt.typeString, func(t *testing.T) {
			assert.Equalf(t, tt.want, Map[tt.typeString], "unexpected type for %s", tt.typeString)
			assert.Equalf(t, tt.typeString, tt.want.String(), "unexpected string for %s", tt.typeString)
		})
	}
}
