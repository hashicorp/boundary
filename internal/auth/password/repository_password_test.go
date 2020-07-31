package password

import (
	"context"
	"errors"
	"testing"

	"github.com/hashicorp/watchtower/internal/auth/password/store"
	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/iam"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRepository_Authenticate(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)

	o, _ := iam.TestScopes(t, conn)
	authMethods := TestAuthMethods(t, conn, o.GetPublicId(), 1)
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

func TestRepository_AuthenticateRehash(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	assert, require := assert.New(t), require.New(t)

	authMethods := testAuthMethods(t, conn, 1)
	authMethod := authMethods[0]
	authMethodId := authMethod.GetPublicId()
	userName := "kazmierczak"
	passwd := "12345678"
	ctx := context.Background()

	repo, err := NewRepository(rw, rw, wrapper)
	assert.NoError(err)
	require.NotNil(repo)

	// Get the default (original) argon2 configuration
	origConf, err := repo.GetConfiguration(ctx, authMethodId)
	assert.NoError(err)
	require.NotNil(origConf)
	origArgonConf, ok := origConf.(*Argon2Configuration)
	require.True(ok, "want *Argon2Configuration")
	require.NotEmpty(origArgonConf.PrivateId, "original configuration PrivateId")
	origConfId := origArgonConf.PrivateId

	// Create an account with a password
	inAcct := &Account{
		Account: &store.Account{
			AuthMethodId: authMethod.PublicId,
			UserName:     userName,
		},
	}

	origAcct, err := repo.CreateAccount(ctx, inAcct, WithPassword(passwd))
	require.NoError(err)
	require.NotNil(origAcct)
	assert.NotEmpty(origAcct.PublicId)

	// Get the credential for the new account and verify the KDF used the
	// original argon2 configuration
	origCred := &Argon2Credential{Argon2Credential: &store.Argon2Credential{}}
	require.NoError(rw.LookupWhere(ctx, origCred, "password_account_id = ?", origAcct.PublicId))
	assert.Equal(origAcct.PublicId, origCred.PasswordAccountId)
	assert.Equal(origConfId, origCred.PasswordConfId)
	assert.Equal(origCred.CreateTime, origCred.UpdateTime, "create and update times are equal")
	origCredId := origCred.PrivateId

	// Authenticate and verify the credential ID
	authAcct, err := repo.Authenticate(ctx, authMethodId, userName, passwd)
	require.NoError(err)
	require.NotNil(authAcct, "auth account")
	assert.Equal(origAcct.PublicId, authAcct.PublicId)
	assert.Equal(origCredId, authAcct.CredentialId)
	auth1CredId := authAcct.CredentialId

	// Get the credential and verify the call to Authenticate did not
	// change anything
	auth1Cred := &Argon2Credential{
		Argon2Credential: &store.Argon2Credential{
			PrivateId: auth1CredId,
		},
	}
	require.NoError(rw.LookupById(ctx, auth1Cred))
	assert.Equal(authAcct.PublicId, auth1Cred.PasswordAccountId)
	assert.Equal(origConfId, auth1Cred.PasswordConfId)
	assert.Equal(origCred.PasswordConfId, auth1Cred.PasswordConfId, "same configuration ID")
	assert.Equal(origCred.Salt, auth1Cred.Salt, "same salt")
	assert.Equal(origCred.DerivedKey, auth1Cred.DerivedKey, "same derived key")
	assert.Equal(origCred.UpdateTime, auth1Cred.UpdateTime, "same update time")

	// Change the argon2 configuration
	inArgonConf := origArgonConf.clone()
	inArgonConf.Threads = origArgonConf.Threads + 1

	upConf, err := repo.SetConfiguration(ctx, inArgonConf)
	require.NoError(err)
	require.NotNil(upConf)
	assert.NotSame(inArgonConf, upConf)

	upArgonConf, ok := upConf.(*Argon2Configuration)
	require.True(ok, "want *Argon2Configuration")
	assert.NotEqual(origConfId, upArgonConf.PrivateId)

	// Authenticate and verify the credential ID has not changed
	auth2Acct, err := repo.Authenticate(ctx, authMethodId, userName, passwd)
	require.NoError(err)
	require.NotNil(auth2Acct, "auth2 account")
	assert.Equal(origAcct.PublicId, auth2Acct.PublicId)
	require.Equal(origCredId, auth2Acct.CredentialId)
	auth2CredId := auth2Acct.CredentialId

	// Get the credential and verify the call to Authenticate changed the
	// appropriate fields
	auth2Cred := &Argon2Credential{
		Argon2Credential: &store.Argon2Credential{
			PrivateId: auth2CredId,
		},
	}
	require.NoError(rw.LookupById(ctx, auth2Cred))
	// Verify fields that should not change
	assert.Equal(auth2Acct.PublicId, auth2Cred.PasswordAccountId)
	assert.Equal(origCred.PrivateId, auth2Cred.PrivateId, "the credential Id should not change")
	assert.Equal(origCred.CreateTime, auth2Cred.CreateTime, "the create time should not change")

	// Verify fields that should change
	require.NoError(auth2Cred.decrypt(ctx, wrapper))
	assert.NotEqual(origCred.UpdateTime, auth2Cred.UpdateTime, "the update time should be different")
	assert.NotEqual(origCred.PasswordConfId, auth2Cred.PasswordConfId, "the configuration Id should be different")
	assert.NotEqual(origCred.Salt, auth2Cred.Salt, "a new salt value should be generated")
	assert.NotEqual(origCred.DerivedKey, auth2Cred.DerivedKey, "the derived key should be different")
}
