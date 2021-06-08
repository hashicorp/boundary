package auth

import (
	"testing"

	"github.com/hashicorp/boundary/internal/auth/oidc"
	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/hashicorp/boundary/internal/intglobals"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSubtype(t *testing.T) {
	tests := []struct {
		subtype     Subtype
		id          string
		wantString  string
		wantSubtype Subtype
	}{
		{
			subtype:     UnknownSubtype,
			id:          "unknownPrefix" + "1234567890",
			wantString:  "unknown",
			wantSubtype: UnknownSubtype,
		},
		{
			subtype:     PasswordSubtype,
			id:          password.AuthMethodPrefix + "1234567890",
			wantString:  "password",
			wantSubtype: PasswordSubtype,
		},
		{
			subtype:     PasswordSubtype,
			id:          intglobals.OldPasswordAccountPrefix + "1234567890",
			wantString:  "password",
			wantSubtype: PasswordSubtype,
		},
		{
			subtype:     PasswordSubtype,
			id:          intglobals.NewPasswordAccountPrefix + "1234567890",
			wantString:  "password",
			wantSubtype: PasswordSubtype,
		},
		{
			subtype:     OidcSubtype,
			id:          oidc.AuthMethodPrefix + "1234567890",
			wantString:  "oidc",
			wantSubtype: OidcSubtype,
		},
		{
			subtype:     OidcSubtype,
			id:          oidc.AccountPrefix + "1234567890",
			wantString:  "oidc",
			wantSubtype: OidcSubtype,
		},
		{
			subtype:     Subtype(1000),
			id:          "unknownPrefix" + "1234567890",
			wantString:  "unknown",
			wantSubtype: UnknownSubtype,
		},
	}
	for _, tt := range tests {
		t.Run(tt.wantString, func(t *testing.T) {
			assert, _ := assert.New(t), require.New(t)
			s := tt.subtype.String()
			assert.Equal(tt.wantString, s)
			assert.Equal(tt.wantSubtype, SubtypeFromType(s))

			typ := SubtypeFromId(tt.id)
			assert.Equal(tt.wantSubtype, typ)
		})
	}
}
