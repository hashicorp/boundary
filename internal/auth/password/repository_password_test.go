package password

import (
	"context"
	"errors"
	"testing"

	"github.com/hashicorp/watchtower/internal/auth/password/store"
	"github.com/hashicorp/watchtower/internal/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRepository_Authenticate(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)

	authMethods := testAuthMethods(t, conn, 1)
	authMethod := authMethods[0]

	inAcct := &Account{
		Account: &store.Account{
			AuthMethodId: authMethod.PublicId,
			UserName:     "kazmierczak",
		},
	}
	passwd := "12345678"

	repo, err := NewRepository(rw, rw, wrapper)
	assert.NoError(t, err)
	require.NotNil(t, repo)
	outAcct, err := repo.CreateAccount(context.Background(), inAcct, WithPassword(passwd))
	assert.NoError(t, err)
	require.NotNil(t, outAcct)

	type args struct {
		authMethodId string
		userName     string
		password     string
	}

	var tests = []struct {
		name      string
		args      args
		want      *Account
		wantIsErr error
	}{
		{
			name: "invalid-no-authMethodId",
			args: args{
				authMethodId: "",
				userName:     inAcct.UserName,
				password:     passwd,
			},
			wantIsErr: db.ErrInvalidParameter,
		},
		{
			name: "invalid-no-userName",
			args: args{
				authMethodId: inAcct.AuthMethodId,
				userName:     "",
				password:     passwd,
			},
			wantIsErr: db.ErrInvalidParameter,
		},
		{
			name: "invalid-no-password",
			args: args{
				authMethodId: inAcct.AuthMethodId,
				userName:     inAcct.UserName,
				password:     "",
			},
			wantIsErr: db.ErrInvalidParameter,
		},
		{
			name: "valid-authenticate",
			args: args{
				authMethodId: inAcct.AuthMethodId,
				userName:     inAcct.UserName,
				password:     passwd,
			},
			want: outAcct,
		},
		{
			name: "wrong-password",
			args: args{
				authMethodId: inAcct.AuthMethodId,
				userName:     inAcct.UserName,
				password:     "foobar",
			},
			want:      nil,
			wantIsErr: nil,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			authAcct, err := repo.Authenticate(context.Background(), tt.args.authMethodId, tt.args.userName, tt.args.password)
			if tt.wantIsErr != nil {
				assert.Truef(errors.Is(err, tt.wantIsErr), "want err: %q got: %q", tt.wantIsErr, err)
				assert.Nil(authAcct, "returned account")
				return
			}
			require.NoError(err)
			if tt.want == nil {
				assert.Nil(authAcct)
				return
			}
			require.NotNil(authAcct, "returned account")
			assert.NotEmpty(authAcct.CredentialId, "CredentialId")
			assert.Equal(tt.args.authMethodId, authAcct.AuthMethodId, "authMethodId")
			assert.Equal(tt.args.userName, authAcct.UserName, "UserName")
		})
	}
}
