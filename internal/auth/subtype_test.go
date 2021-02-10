package auth

import (
	"testing"

	"github.com/hashicorp/boundary/internal/auth/oidc"
	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSubType(t *testing.T) {
	tests := []struct {
		subType     SubType
		id          string
		wantString  string
		wantSubtype SubType
	}{
		{
			subType:     UnknownSubtype,
			id:          "unknownPrefix" + "1234567890",
			wantString:  "unknown",
			wantSubtype: UnknownSubtype,
		},
		{
			subType:     PasswordSubtype,
			id:          password.AuthMethodPrefix + "1234567890",
			wantString:  "password",
			wantSubtype: PasswordSubtype,
		},
		{
			subType:     PasswordSubtype,
			id:          password.AccountPrefix + "1234567890",
			wantString:  "password",
			wantSubtype: PasswordSubtype,
		},
		{
			subType:     OidcSubtype,
			id:          oidc.AuthMethodPrefix + "1234567890",
			wantString:  "oidc",
			wantSubtype: OidcSubtype,
		},
		{
			subType:     OidcSubtype,
			id:          oidc.AccountPrefix + "1234567890",
			wantString:  "oidc",
			wantSubtype: OidcSubtype,
		},
		{
			subType:     SubType(1000),
			id:          "unknownPrefix" + "1234567890",
			wantString:  "unknown",
			wantSubtype: UnknownSubtype,
		},
	}
	for _, tt := range tests {
		t.Run(tt.wantString, func(t *testing.T) {
			assert, _ := assert.New(t), require.New(t)
			s := tt.subType.String()
			assert.Equal(tt.wantString, s)
			assert.Equal(tt.wantSubtype, SubtypeFromType(s))

			typ := SubtypeFromId(tt.id)
			assert.Equal(tt.wantSubtype, typ)
		})
	}
}
