// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package password

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/auth/password/store"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRepository_Authenticate(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	o, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	authMethods := TestAuthMethods(t, conn, o.GetPublicId(), 1)
	authMethod := authMethods[0]

	inAcct := &Account{
		Account: &store.Account{
			AuthMethodId: authMethod.PublicId,
			LoginName:    "kazmierczak",
		},
	}
	passwd := "12345678"

	repo, err := NewRepository(context.Background(), rw, rw, kms)
	assert.NoError(t, err)
	require.NotNil(t, repo)
	outAcct, err := repo.CreateAccount(context.Background(), o.GetPublicId(), inAcct, WithPassword(passwd))
	assert.NoError(t, err)
	require.NotNil(t, outAcct)

	type args struct {
		authMethodId string
		loginName    string
		password     string
	}

	tests := []struct {
		name       string
		args       args
		want       *Account
		wantIsErr  errors.Code
		wantErrMsg string
	}{
		{
			name: "invalid-no-authMethodId",
			args: args{
				authMethodId: "",
				loginName:    inAcct.LoginName,
				password:     passwd,
			},
			wantIsErr:  errors.InvalidParameter,
			wantErrMsg: "password.(Repository).Authenticate: missing authMethodId: parameter violation: error #100",
		},
		{
			name: "invalid-no-loginName",
			args: args{
				authMethodId: inAcct.AuthMethodId,
				loginName:    "",
				password:     passwd,
			},
			wantIsErr:  errors.InvalidParameter,
			wantErrMsg: "password.(Repository).Authenticate: missing loginName: parameter violation: error #100",
		},
		{
			name: "invalid-no-password",
			args: args{
				authMethodId: inAcct.AuthMethodId,
				loginName:    inAcct.LoginName,
				password:     "",
			},
			wantIsErr:  errors.InvalidParameter,
			wantErrMsg: "password.(Repository).Authenticate: missing password: parameter violation: error #100",
		},
		{
			name: "valid-authenticate",
			args: args{
				authMethodId: inAcct.AuthMethodId,
				loginName:    inAcct.LoginName,
				password:     passwd,
			},
			want: outAcct,
		},
		{
			name: "wrong-password",
			args: args{
				authMethodId: inAcct.AuthMethodId,
				loginName:    inAcct.LoginName,
				password:     "foobar",
			},
			want:      nil,
			wantIsErr: errors.Unknown,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			authAcct, err := repo.Authenticate(context.Background(), o.GetPublicId(), tt.args.authMethodId, tt.args.loginName, tt.args.password)
			if tt.wantIsErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantIsErr), err), "Unexpected error %s", err)
				assert.Equal(tt.wantErrMsg, err.Error())
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
			assert.Equal(tt.args.loginName, authAcct.LoginName, "LoginName")
			err = db.TestVerifyOplog(t, rw, authAcct.CredentialId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second))
			assert.Error(err)
			assert.True(errors.IsNotFoundError(err))
		})
	}
}

func TestRepository_AuthenticateRehash(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	assert, require := assert.New(t), require.New(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	o, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	authMethods := TestAuthMethods(t, conn, o.GetPublicId(), 1)
	authMethod := authMethods[0]
	authMethodId := authMethod.GetPublicId()
	loginName := "kazmierczak"
	passwd := "12345678"
	ctx := context.Background()

	repo, err := NewRepository(context.Background(), rw, rw, kmsCache)
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
			LoginName:    loginName,
		},
	}

	origAcct, err := repo.CreateAccount(ctx, o.GetPublicId(), inAcct, WithPassword(passwd))
	require.NoError(err)
	require.NotNil(origAcct)
	assert.NotEmpty(origAcct.PublicId)

	// Get the credential for the new account and verify the KDF used the
	// original argon2 configuration
	origCred := &Argon2Credential{Argon2Credential: &store.Argon2Credential{}}
	require.NoError(rw.LookupWhere(ctx, origCred, "password_account_id = ?", []any{origAcct.PublicId}))
	assert.Equal(origAcct.PublicId, origCred.PasswordAccountId)
	assert.Equal(origConfId, origCred.PasswordConfId)
	assert.Equal(origCred.CreateTime, origCred.UpdateTime, "create and update times are equal")
	origCredId := origCred.PrivateId

	// Authenticate and verify the credential ID
	authAcct, err := repo.Authenticate(ctx, o.GetPublicId(), authMethodId, loginName, passwd)
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

	upConf, err := repo.SetConfiguration(ctx, o.GetPublicId(), inArgonConf)
	require.NoError(err)
	require.NotNil(upConf)
	assert.NotSame(inArgonConf, upConf)

	upArgonConf, ok := upConf.(*Argon2Configuration)
	require.True(ok, "want *Argon2Configuration")
	assert.NotEqual(origConfId, upArgonConf.PrivateId)

	// Change the key used to encrypt the password too, to test
	// that it gets updated appropriately
	err = kmsCache.RotateKeys(ctx, o.GetPublicId())
	require.NoError(err)

	// Authenticate and verify the credential ID has not changed
	auth2Acct, err := repo.Authenticate(ctx, o.GetPublicId(), authMethodId, loginName, passwd)
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
	decryptWrapper, err := kmsCache.GetWrapper(ctx, o.GetPublicId(), kms.KeyPurposeDatabase, kms.WithKeyId(auth2Cred.GetKeyId()))
	require.NoError(err)
	require.NoError(auth2Cred.decrypt(ctx, decryptWrapper))
	assert.NotEqual(origCred.UpdateTime, auth2Cred.UpdateTime, "the update time should be different")
	assert.NotEqual(origCred.PasswordConfId, auth2Cred.PasswordConfId, "the configuration Id should be different")
	assert.NotEqual(origCred.Salt, auth2Cred.Salt, "a new salt value should be generated")
	assert.NotEqual(origCred.DerivedKey, auth2Cred.DerivedKey, "the derived key should be different")
	assert.NotEqual(origCred.KeyId, auth2Cred.KeyId)

	assert.NoError(db.TestVerifyOplog(t, rw, auth2Cred.PrivateId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second)))
}

func TestRepository_ChangePassword(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)

	repo, err := NewRepository(context.Background(), rw, rw, kms)
	require.NoError(t, err)
	require.NotNil(t, repo)

	o, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	authMethod := TestAuthMethods(t, conn, o.GetPublicId(), 1)[0]

	inAcct := &Account{
		Account: &store.Account{
			LoginName:    "kazmierczak",
			AuthMethodId: authMethod.PublicId,
		},
	}
	passwd := "12345678"

	acct, err := repo.CreateAccount(context.Background(), o.GetPublicId(), inAcct, WithPassword(passwd))
	require.NoError(t, err)
	require.NotNil(t, acct)

	type args struct {
		acctId   string
		old, new string
	}

	tests := []struct {
		name        string
		args        args
		wantAccount bool
		wantIsErr   errors.Code
		wantErrMsg  string
	}{
		{
			name: "invalid-no-accountId",
			args: args{
				acctId: "",
				old:    passwd,
				new:    "12345678-changed",
			},
			wantIsErr:  errors.InvalidParameter,
			wantErrMsg: "password.(Repository).ChangePassword: missing account id: parameter violation: error #100",
		},
		{
			name: "invalid-no-current-password",
			args: args{
				acctId: acct.PublicId,
				old:    "",
				new:    "12345678-changed",
			},
			wantIsErr:  errors.InvalidParameter,
			wantErrMsg: "password.(Repository).ChangePassword: missing old password: parameter violation: error #100",
		},
		{
			name: "invalid-no-new-password",
			args: args{
				acctId: acct.PublicId,
				old:    passwd,
				new:    "",
			},
			wantIsErr:  errors.InvalidParameter,
			wantErrMsg: "password.(Repository).ChangePassword: missing new password: parameter violation: error #100",
		},
		{
			name: "invalid-same-passwords",
			args: args{
				acctId: acct.PublicId,
				old:    passwd,
				new:    passwd,
			},
			wantIsErr:  errors.PasswordsEqual,
			wantErrMsg: "password.(Repository).ChangePassword: passwords must not equal: password violation: error #203",
		},
		{
			name: "auth-failure-unknown-accountId",
			args: args{
				acctId: "not-an-account-Id",
				old:    passwd,
				new:    "12345678-changed",
			},
			wantAccount: false,
			wantIsErr:   errors.RecordNotFound,
			wantErrMsg:  "password.(Repository).ChangePassword: account not found: search issue: error #1100",
		},
		{
			name: "auth-failure-wrong-current-password",
			args: args{
				acctId: acct.PublicId,
				old:    "wrong-password",
				new:    "12345678-changed",
			},
			wantAccount: false,
		},
		{
			name: "password-too-short",
			args: args{
				acctId: acct.PublicId,
				old:    passwd,
				new:    "1",
			},
			wantIsErr:  errors.PasswordTooShort,
			wantErrMsg: "password.(Repository).ChangePassword: must be at least 8: password violation: error #200",
		},
		{
			name: "valid",
			args: args{
				acctId: acct.PublicId,
				old:    passwd,
				new:    "12345678-changed",
			},
			wantAccount: true,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			// Calls to Authenticate should always succeed in these tests
			authFn := func(pwd string, name string) *Account {
				acct, err := repo.Authenticate(context.Background(), o.GetPublicId(), inAcct.AuthMethodId, inAcct.LoginName, pwd)
				require.NotNilf(acct, "%s: Authenticate should return an account", name)
				require.NoErrorf(err, "%s: Authenticate should succeed", name)
				return acct
			}
			// authenticate with original password
			authAcct1 := authFn(passwd, "original account")

			chgAuthAcct, err := repo.ChangePassword(context.Background(), o.GetPublicId(), tt.args.acctId, tt.args.old, tt.args.new, authAcct1.Version)
			if tt.wantIsErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantIsErr), err), "Unexpected error %s", err)
				assert.Equal(tt.wantErrMsg, err.Error())
				assert.Nil(chgAuthAcct, "returned account")
				authAcct2 := authFn(passwd, "error changing password: using old password")
				assert.Equal(authAcct1.CredentialId, authAcct2.CredentialId, "CredentialId should not change")
				return
			}
			assert.NoError(err)
			if !tt.wantAccount {
				assert.Nil(chgAuthAcct)
				authAcct2 := authFn(passwd, "no account from changing password: using old password")
				assert.Equal(authAcct1.CredentialId, authAcct2.CredentialId, "CredentialId should not change")
				return
			}
			require.NotNil(chgAuthAcct, "returned account")
			assert.NotEmpty(chgAuthAcct.CredentialId, "CredentialId")
			assert.NotEqual(authAcct1.CredentialId, chgAuthAcct.CredentialId, "CredentialId should change")
			assert.Equal(authAcct1.AuthMethodId, chgAuthAcct.AuthMethodId, "authMethodId")
			assert.Equal(authAcct1.LoginName, chgAuthAcct.LoginName, "LoginName")

			authAcct2 := authFn(tt.args.new, "successful change password: using new password")
			assert.Equal(chgAuthAcct.CredentialId, authAcct2.CredentialId, "CredentialId should not change")

			assert.NoError(db.TestVerifyOplog(t, rw, authAcct1.CredentialId, db.WithOperation(oplog.OpType_OP_TYPE_DELETE), db.WithCreateNotBefore(10*time.Second)))
			assert.NoError(db.TestVerifyOplog(t, rw, authAcct2.CredentialId, db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second)))
		})
	}
}

func TestRepository_SetPassword(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)

	repo, err := NewRepository(context.Background(), rw, rw, kms)
	require.NoError(t, err)
	require.NotNil(t, repo)

	o, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	authMethod := TestAuthMethods(t, conn, o.GetPublicId(), 1)[0]

	origPasswd := "12345678"

	createAccount := func(un string) func(string) *Account {
		return func(pw string) *Account {
			inAcct := &Account{
				Account: &store.Account{
					AuthMethodId: authMethod.PublicId,
					LoginName:    un,
				},
			}
			var opts []Option
			if pw != "" {
				opts = append(opts, WithPassword(origPasswd))
			}
			acct, err := repo.CreateAccount(context.Background(), o.GetPublicId(), inAcct, opts...)
			require.NoError(t, err)
			require.NotNil(t, acct)
			return acct
		}
	}

	wantAuthenticate := func(t *testing.T, ln, pw, msg string) string {
		acct, err := repo.Authenticate(context.Background(), o.GetPublicId(), authMethod.PublicId, ln, pw)
		assert.NoErrorf(t, err, "%s: authenticate should not return an error", msg)
		if assert.NotNilf(t, acct, "%s: authenticate should succeed", msg) {
			return acct.CredentialId
		}
		return ""
	}
	wantNoAuthenticate := func(t *testing.T, ln, pw, msg string) string {
		acct, err := repo.Authenticate(context.Background(), o.GetPublicId(), authMethod.PublicId, ln, pw)
		assert.NoErrorf(t, err, "%s: authenticate should not return an error", msg)
		assert.Nilf(t, acct, "%s: authenticate should not succeed", msg)
		return ""
	}

	tests := []struct {
		name       string
		oldPw      string
		newPw      string
		createAcct func(string) *Account
	}{
		{
			name:       "valid-new-password-no-current-password",
			createAcct: createAccount("validnewpwnoold"),
			oldPw:      "",
			newPw:      "abcdefghijk",
		},
		{
			name:       "valid-new-password-delete-current-password",
			createAcct: createAccount("validnewpwyesold"),
			oldPw:      origPasswd,
			newPw:      "abcdefghijk",
		},
		{
			name:       "valid-delete-password-no-new-password",
			createAcct: createAccount("nonewyesold"),
			oldPw:      origPasswd,
			newPw:      "",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			acct := tt.createAcct(tt.oldPw)

			nextAuth := wantNoAuthenticate
			if tt.oldPw != "" {
				nextAuth = wantAuthenticate
			}
			oldCredId := nextAuth(t, acct.LoginName, origPasswd, "after create account")

			acct, err = repo.SetPassword(context.Background(), o.GetPublicId(), acct.PublicId, tt.newPw, acct.Version)
			require.NoError(err)

			if oldCredId != "" {
				wantNoAuthenticate(t, acct.LoginName, origPasswd, "old password")
				assert.NoError(db.TestVerifyOplog(t, rw, oldCredId, db.WithOperation(oplog.OpType_OP_TYPE_DELETE), db.WithCreateNotBefore(10*time.Second)))
			}
			if tt.newPw != "" {
				newCredId := wantAuthenticate(t, acct.LoginName, tt.newPw, "new password")
				assert.NotEqual(oldCredId, newCredId)
				assert.NoError(db.TestVerifyOplog(t, rw, newCredId, db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second)))
			}
		})
	}

	badInputAcct := createAccount("badinputusername")("")
	badInputCases := []struct {
		name       string
		accountId  string
		pw         string
		version    uint32
		wantIsErr  errors.Code
		wantErrMsg string
	}{
		{
			name:       "no id",
			pw:         "anylongpassword",
			version:    1,
			wantIsErr:  errors.InvalidParameter,
			wantErrMsg: "password.(Repository).SetPassword: missing accountId: parameter violation: error #100",
		},
		{
			name:       "short pw",
			accountId:  badInputAcct.PublicId,
			pw:         "c",
			version:    1,
			wantIsErr:  errors.PasswordTooShort,
			wantErrMsg: "password.(Repository).SetPassword: password must be at least 8: password violation: error #200",
		},
		{
			name:       "no version",
			accountId:  badInputAcct.PublicId,
			pw:         "anylongpassword",
			wantIsErr:  errors.InvalidParameter,
			wantErrMsg: "password.(Repository).SetPassword: missing version: parameter violation: error #100",
		},
	}
	for _, tt := range badInputCases {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)

			acct, err := repo.SetPassword(context.Background(), o.GetPublicId(), tt.accountId, tt.pw, tt.version)
			assert.Error(err)
			assert.Truef(errors.Match(errors.T(tt.wantIsErr), err), "Unexpected error %s", err)
			assert.Equal(tt.wantErrMsg, err.Error())
			assert.Nil(acct)
		})
	}
}
