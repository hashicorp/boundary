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
			typeString: "auth-method",
			want:       AuthMethod,
		},
		{
			typeString: "account",
			want:       Account,
		},
		{
			typeString: "auth-token",
			want:       AuthToken,
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
			typeString: "controller",
			want:       Controller,
		},
		{
			typeString: "worker",
			want:       Worker,
		},
		{
			typeString: "session",
			want:       Session,
		},
		{
			typeString: "managed-group",
			want:       ManagedGroup,
		},
		{
			typeString: "credential-store",
			want:       CredentialStore,
		},
		{
			typeString: "credential-library",
			want:       CredentialLibrary,
		},
	}
	for _, tt := range tests {
		t.Run(tt.typeString, func(t *testing.T) {
			assert.Equalf(t, tt.want, Map[tt.typeString], "unexpected type for %s", tt.typeString)
			assert.Equalf(t, tt.typeString, tt.want.String(), "unexpected string for %s", tt.typeString)
		})
	}
}
