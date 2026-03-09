// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package ldap

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRewrap_bindCredentialRewrapFn(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	testRootWrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, conn, testRootWrapper)
	rw := db.New(conn)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, testRootWrapper))
	orgDBWrapper, err := testKms.GetWrapper(testCtx, org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)
	tests := []struct {
		name            string
		ctx             context.Context
		setup           func() (string, string, *BindCredential, *AuthMethod)
		reader          db.Reader
		writer          db.Writer
		kmsRepo         kms.GetWrapperer
		wantErr         bool
		wantErrCode     errors.Code
		wantErrContains string
	}{
		{
			name: "success",
			ctx:  testCtx,
			setup: func() (string, string, *BindCredential, *AuthMethod) {
				am := TestAuthMethod(t, conn, orgDBWrapper, org.PublicId, []string{"ldaps://alice.com"}, WithBindCredential(testCtx, "bind-dn", "bind-password"))
				bc := allocBindCredential()
				err = rw.LookupWhere(testCtx, &bc, "ldap_method_id = ?", []any{am.PublicId})
				require.NoError(t, err)
				require.NoError(t, bc.decrypt(testCtx, orgDBWrapper))
				assert.NotEmpty(t, bc.GetKeyId())
				assert.NotEmpty(t, bc.GetPassword())
				assert.NotEmpty(t, bc.GetPasswordHmac())
				assert.NotEmpty(t, bc.GetCtPassword())
				return bc.GetKeyId(), am.GetScopeId(), bc, am
			},
			reader:  rw,
			writer:  rw,
			kmsRepo: testKms,
		},
		{
			name: "missing-key-id",
			ctx:  testCtx,
			setup: func() (string, string, *BindCredential, *AuthMethod) {
				am := TestAuthMethod(t, conn, orgDBWrapper, org.PublicId, []string{"ldaps://alice.com"}, WithBindCredential(testCtx, "bind-dn", "bind-password"))
				bc := allocBindCredential()
				err = rw.LookupWhere(testCtx, &bc, "ldap_method_id = ?", []any{am.PublicId})
				require.NoError(t, err)
				require.NoError(t, bc.decrypt(testCtx, orgDBWrapper))
				assert.NotEmpty(t, bc.GetKeyId())
				assert.NotEmpty(t, bc.GetPassword())
				assert.NotEmpty(t, bc.GetPasswordHmac())
				assert.NotEmpty(t, bc.GetCtPassword())
				return "", am.GetScopeId(), bc, am
			},
			reader:          rw,
			writer:          rw,
			kmsRepo:         testKms,
			wantErr:         true,
			wantErrCode:     errors.InvalidParameter,
			wantErrContains: "missing data key version id",
		},
		{
			name: "missing-scope-id",
			ctx:  testCtx,
			setup: func() (string, string, *BindCredential, *AuthMethod) {
				am := TestAuthMethod(t, conn, orgDBWrapper, org.PublicId, []string{"ldaps://alice.com"}, WithBindCredential(testCtx, "bind-dn", "bind-password"))
				bc := allocBindCredential()
				err = rw.LookupWhere(testCtx, &bc, "ldap_method_id = ?", []any{am.PublicId})
				require.NoError(t, err)
				require.NoError(t, bc.decrypt(testCtx, orgDBWrapper))
				assert.NotEmpty(t, bc.GetKeyId())
				assert.NotEmpty(t, bc.GetPassword())
				assert.NotEmpty(t, bc.GetPasswordHmac())
				assert.NotEmpty(t, bc.GetCtPassword())
				return bc.GetKeyId(), "", bc, am
			},
			reader:          rw,
			writer:          rw,
			kmsRepo:         testKms,
			wantErr:         true,
			wantErrCode:     errors.InvalidParameter,
			wantErrContains: "missing scope id",
		},
		{
			name: "missing-reader",
			ctx:  testCtx,
			setup: func() (string, string, *BindCredential, *AuthMethod) {
				am := TestAuthMethod(t, conn, orgDBWrapper, org.PublicId, []string{"ldaps://alice.com"}, WithBindCredential(testCtx, "bind-dn", "bind-password"))
				bc := allocBindCredential()
				err = rw.LookupWhere(testCtx, &bc, "ldap_method_id = ?", []any{am.PublicId})
				require.NoError(t, err)
				require.NoError(t, bc.decrypt(testCtx, orgDBWrapper))
				assert.NotEmpty(t, bc.GetKeyId())
				assert.NotEmpty(t, bc.GetPassword())
				assert.NotEmpty(t, bc.GetPasswordHmac())
				assert.NotEmpty(t, bc.GetCtPassword())
				return bc.GetKeyId(), am.GetScopeId(), bc, am
			},
			reader:          nil,
			writer:          rw,
			kmsRepo:         testKms,
			wantErr:         true,
			wantErrCode:     errors.InvalidParameter,
			wantErrContains: "missing database reader",
		},
		{
			name: "missing-writer",
			ctx:  testCtx,
			setup: func() (string, string, *BindCredential, *AuthMethod) {
				am := TestAuthMethod(t, conn, orgDBWrapper, org.PublicId, []string{"ldaps://alice.com"}, WithBindCredential(testCtx, "bind-dn", "bind-password"))
				bc := allocBindCredential()
				err = rw.LookupWhere(testCtx, &bc, "ldap_method_id = ?", []any{am.PublicId})
				require.NoError(t, err)
				require.NoError(t, bc.decrypt(testCtx, orgDBWrapper))
				assert.NotEmpty(t, bc.GetKeyId())
				assert.NotEmpty(t, bc.GetPassword())
				assert.NotEmpty(t, bc.GetPasswordHmac())
				assert.NotEmpty(t, bc.GetCtPassword())
				return bc.GetKeyId(), am.GetScopeId(), bc, am
			},
			reader:          rw,
			writer:          nil,
			kmsRepo:         testKms,
			wantErr:         true,
			wantErrCode:     errors.InvalidParameter,
			wantErrContains: "missing database writer",
		},
		{
			name: "missing-kms",
			ctx:  testCtx,
			setup: func() (string, string, *BindCredential, *AuthMethod) {
				am := TestAuthMethod(t, conn, orgDBWrapper, org.PublicId, []string{"ldaps://alice.com"}, WithBindCredential(testCtx, "bind-dn", "bind-password"))
				bc := allocBindCredential()
				err = rw.LookupWhere(testCtx, &bc, "ldap_method_id = ?", []any{am.PublicId})
				require.NoError(t, err)
				require.NoError(t, bc.decrypt(testCtx, orgDBWrapper))
				assert.NotEmpty(t, bc.GetKeyId())
				assert.NotEmpty(t, bc.GetPassword())
				assert.NotEmpty(t, bc.GetPasswordHmac())
				assert.NotEmpty(t, bc.GetCtPassword())
				return bc.GetKeyId(), am.GetScopeId(), bc, am
			},
			reader:          rw,
			writer:          rw,
			kmsRepo:         nil,
			wantErr:         true,
			wantErrCode:     errors.InvalidParameter,
			wantErrContains: "missing kms repository",
		},
		{
			name: "GetWrapper-err",
			ctx:  testCtx,
			setup: func() (string, string, *BindCredential, *AuthMethod) {
				am := TestAuthMethod(t, conn, orgDBWrapper, org.PublicId, []string{"ldaps://alice.com"}, WithBindCredential(testCtx, "bind-dn", "bind-password"))
				bc := allocBindCredential()
				err = rw.LookupWhere(testCtx, &bc, "ldap_method_id = ?", []any{am.PublicId})
				require.NoError(t, err)
				require.NoError(t, bc.decrypt(testCtx, orgDBWrapper))
				assert.NotEmpty(t, bc.GetKeyId())
				assert.NotEmpty(t, bc.GetPassword())
				assert.NotEmpty(t, bc.GetPasswordHmac())
				assert.NotEmpty(t, bc.GetCtPassword())
				return bc.GetKeyId(), am.GetScopeId(), bc, am
			},
			reader: rw,
			writer: rw,
			kmsRepo: &kms.MockGetWrapperer{
				GetErr: errors.New(testCtx, errors.Internal, "test", "GetWrapper error"),
			},
			wantErr:         true,
			wantErrCode:     errors.Internal,
			wantErrContains: "GetWrapper error",
		},
		{
			name: "encrypt-err",
			ctx:  testCtx,
			setup: func() (string, string, *BindCredential, *AuthMethod) {
				am := TestAuthMethod(t, conn, orgDBWrapper, org.PublicId, []string{"ldaps://alice.com"}, WithBindCredential(testCtx, "bind-dn", "bind-password"))
				bc := allocBindCredential()
				err = rw.LookupWhere(testCtx, &bc, "ldap_method_id = ?", []any{am.PublicId})
				require.NoError(t, err)
				require.NoError(t, bc.decrypt(testCtx, orgDBWrapper))
				assert.NotEmpty(t, bc.GetKeyId())
				assert.NotEmpty(t, bc.GetPassword())
				assert.NotEmpty(t, bc.GetPasswordHmac())
				assert.NotEmpty(t, bc.GetCtPassword())
				return bc.GetKeyId(), am.GetScopeId(), bc, am
			},
			reader: rw,
			writer: rw,
			kmsRepo: &kms.MockGetWrapperer{
				ReturnWrapper: &kms.MockWrapper{
					EncryptErr: errors.New(testCtx, errors.Encrypt, "test", "encrypt error"),
					Wrapper:    orgDBWrapper,
				},
			},
			wantErr:         true,
			wantErrCode:     errors.Encrypt,
			wantErrContains: "encrypt error",
		},
		{
			name: "decrypt-err",
			ctx:  testCtx,
			setup: func() (string, string, *BindCredential, *AuthMethod) {
				am := TestAuthMethod(t, conn, orgDBWrapper, org.PublicId, []string{"ldaps://alice.com"}, WithBindCredential(testCtx, "bind-dn", "bind-password"))
				bc := allocBindCredential()
				err = rw.LookupWhere(testCtx, &bc, "ldap_method_id = ?", []any{am.PublicId})
				require.NoError(t, err)
				require.NoError(t, bc.decrypt(testCtx, orgDBWrapper))
				assert.NotEmpty(t, bc.GetKeyId())
				assert.NotEmpty(t, bc.GetPassword())
				assert.NotEmpty(t, bc.GetPasswordHmac())
				assert.NotEmpty(t, bc.GetCtPassword())
				return bc.GetKeyId(), am.GetScopeId(), bc, am
			},
			reader: rw,
			writer: rw,
			kmsRepo: &kms.MockGetWrapperer{
				ReturnWrapper: &kms.MockWrapper{
					DecryptErr: errors.New(testCtx, errors.Encrypt, "test", "decrypt error"),
					Wrapper:    orgDBWrapper,
				},
			},
			wantErr:         true,
			wantErrCode:     errors.Decrypt,
			wantErrContains: "decrypt error",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			keyId, scopeId, bc, am := tc.setup()

			// now we can rotate and rewrap
			assert.NoError(testKms.RotateKeys(testCtx, org.Scope.GetPublicId()))

			// let's do this rewrapping!
			err := bindCredentialRewrapFn(tc.ctx, keyId, scopeId, tc.reader, tc.writer, tc.kmsRepo)
			if tc.wantErr {
				require.Error(err)
				if tc.wantErrCode != errors.Unknown {
					assert.True(errors.Match(errors.T(tc.wantErrCode), err))
				}
				if tc.wantErrContains != "" {
					assert.Contains(err.Error(), tc.wantErrContains)
				}
				return
			}
			require.NoError(err)

			// fetch the new key version
			kmsWrapper, err := testKms.GetWrapper(testCtx, org.Scope.GetPublicId(), kms.KeyPurposeDatabase)
			assert.NoError(err)
			newKeyVersion, err := kmsWrapper.KeyId(testCtx)
			assert.NoError(err)

			// get the latest bind cred
			latestBindCred := allocBindCredential()
			err = rw.LookupWhere(testCtx, &latestBindCred, "ldap_method_id = ?", []any{am.GetPublicId()})
			require.NoError(err)
			require.NoError(latestBindCred.decrypt(testCtx, kmsWrapper))

			// make sure the password and its hmac are correct and that it uses
			// the newest key version id
			assert.NotEmpty(latestBindCred.KeyId)
			assert.Equal(newKeyVersion, latestBindCred.KeyId)
			assert.Equal([]byte("bind-password"), latestBindCred.Password)
			assert.NotEqual(bc.CtPassword, latestBindCred.CtPassword)
			assert.NotEmpty(latestBindCred.PasswordHmac)
			assert.Equal(bc.PasswordHmac, latestBindCred.PasswordHmac)
		})
	}
}

func TestRewrap_clientCertificateRewrapFn(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	testRootWrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, conn, testRootWrapper)
	rw := db.New(conn)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, testRootWrapper))
	orgDBWrapper, err := testKms.GetWrapper(testCtx, org.GetPublicId(), kms.KeyPurposeDatabase)
	require.NoError(t, err)
	tests := []struct {
		name            string
		ctx             context.Context
		setup           func() (string, string, *ClientCertificate, *AuthMethod)
		reader          db.Reader
		writer          db.Writer
		kmsRepo         kms.GetWrapperer
		wantErr         bool
		wantErrCode     errors.Code
		wantErrContains string
	}{
		{
			name: "success",
			ctx:  testCtx,
			setup: func() (string, string, *ClientCertificate, *AuthMethod) {
				_, privKey, err := ed25519.GenerateKey(rand.Reader)
				require.NoError(t, err)
				cert, _ := TestGenerateCA(t, "localhost")
				derPrivKey, err := x509.MarshalPKCS8PrivateKey(privKey)
				require.NoError(t, err)
				am := TestAuthMethod(t, conn, orgDBWrapper, org.PublicId, []string{"ldaps://alice.com"}, WithClientCertificate(testCtx, derPrivKey, cert))
				cc := allocClientCertificate()
				err = rw.LookupWhere(testCtx, &cc, "ldap_method_id = ?", []any{am.GetPublicId()})
				require.NoError(t, err)
				require.NoError(t, cc.decrypt(testCtx, orgDBWrapper))
				assert.NotEmpty(t, cc.GetKeyId())
				assert.NotEmpty(t, cc.GetCertificateKey())
				assert.NotEmpty(t, cc.GetCertificateKeyHmac())
				assert.NotEmpty(t, cc.GetCtCertificateKey())
				return cc.GetKeyId(), am.GetScopeId(), cc, am
			},
			reader:  rw,
			writer:  rw,
			kmsRepo: testKms,
		},
		{
			name: "missing-key-id",
			ctx:  testCtx,
			setup: func() (string, string, *ClientCertificate, *AuthMethod) {
				_, privKey, err := ed25519.GenerateKey(rand.Reader)
				require.NoError(t, err)
				cert, _ := TestGenerateCA(t, "localhost")
				derPrivKey, err := x509.MarshalPKCS8PrivateKey(privKey)
				require.NoError(t, err)
				am := TestAuthMethod(t, conn, orgDBWrapper, org.PublicId, []string{"ldaps://alice.com"}, WithClientCertificate(testCtx, derPrivKey, cert))
				cc := allocClientCertificate()
				err = rw.LookupWhere(testCtx, &cc, "ldap_method_id = ?", []any{am.GetPublicId()})
				require.NoError(t, err)
				require.NoError(t, cc.decrypt(testCtx, orgDBWrapper))
				assert.NotEmpty(t, cc.GetKeyId())
				assert.NotEmpty(t, cc.GetCertificateKey())
				assert.NotEmpty(t, cc.GetCertificateKeyHmac())
				assert.NotEmpty(t, cc.GetCtCertificateKey())
				return "", am.GetScopeId(), cc, am
			},
			reader:          rw,
			writer:          rw,
			kmsRepo:         testKms,
			wantErr:         true,
			wantErrCode:     errors.InvalidParameter,
			wantErrContains: "missing data key version id",
		},
		{
			name: "missing-scope-id",
			ctx:  testCtx,
			setup: func() (string, string, *ClientCertificate, *AuthMethod) {
				_, privKey, err := ed25519.GenerateKey(rand.Reader)
				require.NoError(t, err)
				cert, _ := TestGenerateCA(t, "localhost")
				derPrivKey, err := x509.MarshalPKCS8PrivateKey(privKey)
				require.NoError(t, err)
				am := TestAuthMethod(t, conn, orgDBWrapper, org.PublicId, []string{"ldaps://alice.com"}, WithClientCertificate(testCtx, derPrivKey, cert))
				cc := allocClientCertificate()
				err = rw.LookupWhere(testCtx, &cc, "ldap_method_id = ?", []any{am.GetPublicId()})
				require.NoError(t, err)
				require.NoError(t, cc.decrypt(testCtx, orgDBWrapper))
				assert.NotEmpty(t, cc.GetKeyId())
				assert.NotEmpty(t, cc.GetCertificateKey())
				assert.NotEmpty(t, cc.GetCertificateKeyHmac())
				assert.NotEmpty(t, cc.GetCtCertificateKey())
				return cc.GetKeyId(), "", cc, am
			},
			reader:          rw,
			writer:          rw,
			kmsRepo:         testKms,
			wantErr:         true,
			wantErrCode:     errors.InvalidParameter,
			wantErrContains: "missing scope id",
		},
		{
			name: "missing-reader",
			ctx:  testCtx,
			setup: func() (string, string, *ClientCertificate, *AuthMethod) {
				_, privKey, err := ed25519.GenerateKey(rand.Reader)
				require.NoError(t, err)
				cert, _ := TestGenerateCA(t, "localhost")
				derPrivKey, err := x509.MarshalPKCS8PrivateKey(privKey)
				require.NoError(t, err)
				am := TestAuthMethod(t, conn, orgDBWrapper, org.PublicId, []string{"ldaps://alice.com"}, WithClientCertificate(testCtx, derPrivKey, cert))
				cc := allocClientCertificate()
				err = rw.LookupWhere(testCtx, &cc, "ldap_method_id = ?", []any{am.GetPublicId()})
				require.NoError(t, err)
				require.NoError(t, cc.decrypt(testCtx, orgDBWrapper))
				assert.NotEmpty(t, cc.GetKeyId())
				assert.NotEmpty(t, cc.GetCertificateKey())
				assert.NotEmpty(t, cc.GetCertificateKeyHmac())
				assert.NotEmpty(t, cc.GetCtCertificateKey())
				return cc.GetKeyId(), am.GetScopeId(), cc, am
			},
			reader:          nil,
			writer:          rw,
			kmsRepo:         testKms,
			wantErr:         true,
			wantErrCode:     errors.InvalidParameter,
			wantErrContains: "missing database reader",
		},
		{
			name: "missing-writer",
			ctx:  testCtx,
			setup: func() (string, string, *ClientCertificate, *AuthMethod) {
				_, privKey, err := ed25519.GenerateKey(rand.Reader)
				require.NoError(t, err)
				cert, _ := TestGenerateCA(t, "localhost")
				derPrivKey, err := x509.MarshalPKCS8PrivateKey(privKey)
				require.NoError(t, err)
				am := TestAuthMethod(t, conn, orgDBWrapper, org.PublicId, []string{"ldaps://alice.com"}, WithClientCertificate(testCtx, derPrivKey, cert))
				cc := allocClientCertificate()
				err = rw.LookupWhere(testCtx, &cc, "ldap_method_id = ?", []any{am.GetPublicId()})
				require.NoError(t, err)
				require.NoError(t, cc.decrypt(testCtx, orgDBWrapper))
				assert.NotEmpty(t, cc.GetKeyId())
				assert.NotEmpty(t, cc.GetCertificateKey())
				assert.NotEmpty(t, cc.GetCertificateKeyHmac())
				assert.NotEmpty(t, cc.GetCtCertificateKey())
				return cc.GetKeyId(), am.GetScopeId(), cc, am
			},
			reader:          rw,
			writer:          nil,
			kmsRepo:         testKms,
			wantErr:         true,
			wantErrCode:     errors.InvalidParameter,
			wantErrContains: "missing database writer",
		},
		{
			name: "missing-kms",
			ctx:  testCtx,
			setup: func() (string, string, *ClientCertificate, *AuthMethod) {
				_, privKey, err := ed25519.GenerateKey(rand.Reader)
				require.NoError(t, err)
				cert, _ := TestGenerateCA(t, "localhost")
				derPrivKey, err := x509.MarshalPKCS8PrivateKey(privKey)
				require.NoError(t, err)
				am := TestAuthMethod(t, conn, orgDBWrapper, org.PublicId, []string{"ldaps://alice.com"}, WithClientCertificate(testCtx, derPrivKey, cert))
				cc := allocClientCertificate()
				err = rw.LookupWhere(testCtx, &cc, "ldap_method_id = ?", []any{am.GetPublicId()})
				require.NoError(t, err)
				require.NoError(t, cc.decrypt(testCtx, orgDBWrapper))
				assert.NotEmpty(t, cc.GetKeyId())
				assert.NotEmpty(t, cc.GetCertificateKey())
				assert.NotEmpty(t, cc.GetCertificateKeyHmac())
				assert.NotEmpty(t, cc.GetCtCertificateKey())
				return cc.GetKeyId(), am.GetScopeId(), cc, am
			},
			reader:          rw,
			writer:          rw,
			kmsRepo:         nil,
			wantErr:         true,
			wantErrCode:     errors.InvalidParameter,
			wantErrContains: "missing kms repository",
		},
		{
			name: "GetWrapper-err",
			ctx:  testCtx,
			setup: func() (string, string, *ClientCertificate, *AuthMethod) {
				_, privKey, err := ed25519.GenerateKey(rand.Reader)
				require.NoError(t, err)
				cert, _ := TestGenerateCA(t, "localhost")
				derPrivKey, err := x509.MarshalPKCS8PrivateKey(privKey)
				require.NoError(t, err)
				am := TestAuthMethod(t, conn, orgDBWrapper, org.PublicId, []string{"ldaps://alice.com"}, WithClientCertificate(testCtx, derPrivKey, cert))
				cc := allocClientCertificate()
				err = rw.LookupWhere(testCtx, &cc, "ldap_method_id = ?", []any{am.GetPublicId()})
				require.NoError(t, err)
				require.NoError(t, cc.decrypt(testCtx, orgDBWrapper))
				assert.NotEmpty(t, cc.GetKeyId())
				assert.NotEmpty(t, cc.GetCertificateKey())
				assert.NotEmpty(t, cc.GetCertificateKeyHmac())
				assert.NotEmpty(t, cc.GetCtCertificateKey())
				return cc.GetKeyId(), am.GetScopeId(), cc, am
			},
			reader: rw,
			writer: rw,
			kmsRepo: &kms.MockGetWrapperer{
				GetErr: errors.New(testCtx, errors.Internal, "test", "GetWrapper error"),
			},
			wantErr:         true,
			wantErrCode:     errors.Internal,
			wantErrContains: "GetWrapper error",
		},
		{
			name: "encrypt-err",
			ctx:  testCtx,
			setup: func() (string, string, *ClientCertificate, *AuthMethod) {
				_, privKey, err := ed25519.GenerateKey(rand.Reader)
				require.NoError(t, err)
				cert, _ := TestGenerateCA(t, "localhost")
				derPrivKey, err := x509.MarshalPKCS8PrivateKey(privKey)
				require.NoError(t, err)
				am := TestAuthMethod(t, conn, orgDBWrapper, org.PublicId, []string{"ldaps://alice.com"}, WithClientCertificate(testCtx, derPrivKey, cert))
				cc := allocClientCertificate()
				err = rw.LookupWhere(testCtx, &cc, "ldap_method_id = ?", []any{am.GetPublicId()})
				require.NoError(t, err)
				require.NoError(t, cc.decrypt(testCtx, orgDBWrapper))
				assert.NotEmpty(t, cc.GetKeyId())
				assert.NotEmpty(t, cc.GetCertificateKey())
				assert.NotEmpty(t, cc.GetCertificateKeyHmac())
				assert.NotEmpty(t, cc.GetCtCertificateKey())
				return cc.GetKeyId(), am.GetScopeId(), cc, am
			},
			reader: rw,
			writer: rw,
			kmsRepo: &kms.MockGetWrapperer{
				ReturnWrapper: &kms.MockWrapper{
					EncryptErr: errors.New(testCtx, errors.Encrypt, "test", "encrypt error"),
					Wrapper:    orgDBWrapper,
				},
			},
			wantErr:         true,
			wantErrCode:     errors.Encrypt,
			wantErrContains: "encrypt error",
		},
		{
			name: "decrypt-err",
			ctx:  testCtx,
			setup: func() (string, string, *ClientCertificate, *AuthMethod) {
				_, privKey, err := ed25519.GenerateKey(rand.Reader)
				require.NoError(t, err)
				cert, _ := TestGenerateCA(t, "localhost")
				derPrivKey, err := x509.MarshalPKCS8PrivateKey(privKey)
				require.NoError(t, err)
				am := TestAuthMethod(t, conn, orgDBWrapper, org.PublicId, []string{"ldaps://alice.com"}, WithClientCertificate(testCtx, derPrivKey, cert))
				cc := allocClientCertificate()
				err = rw.LookupWhere(testCtx, &cc, "ldap_method_id = ?", []any{am.GetPublicId()})
				require.NoError(t, err)
				require.NoError(t, cc.decrypt(testCtx, orgDBWrapper))
				assert.NotEmpty(t, cc.GetKeyId())
				assert.NotEmpty(t, cc.GetCertificateKey())
				assert.NotEmpty(t, cc.GetCertificateKeyHmac())
				assert.NotEmpty(t, cc.GetCtCertificateKey())
				return cc.GetKeyId(), am.GetScopeId(), cc, am
			},
			reader: rw,
			writer: rw,
			kmsRepo: &kms.MockGetWrapperer{
				ReturnWrapper: &kms.MockWrapper{
					DecryptErr: errors.New(testCtx, errors.Encrypt, "test", "decrypt error"),
					Wrapper:    orgDBWrapper,
				},
			},
			wantErr:         true,
			wantErrCode:     errors.Decrypt,
			wantErrContains: "decrypt error",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			keyId, scopeId, cc, am := tc.setup()

			// now we can rotate and rewrap
			assert.NoError(testKms.RotateKeys(testCtx, org.Scope.GetPublicId()))

			// let's do this rewrapping!
			err := clientCertificateRewrapFn(tc.ctx, keyId, scopeId, tc.reader, tc.writer, tc.kmsRepo)
			if tc.wantErr {
				require.Error(err)
				if tc.wantErrCode != errors.Unknown {
					assert.True(errors.Match(errors.T(tc.wantErrCode), err))
				}
				if tc.wantErrContains != "" {
					assert.Contains(err.Error(), tc.wantErrContains)
				}
				return
			}
			require.NoError(err)

			// fetch the new key version
			kmsWrapper, err := testKms.GetWrapper(testCtx, org.Scope.GetPublicId(), kms.KeyPurposeDatabase)
			assert.NoError(err)
			newKeyVersion, err := kmsWrapper.KeyId(testCtx)
			assert.NoError(err)

			// get the latest bind cred
			latest := allocClientCertificate()
			err = rw.LookupWhere(testCtx, &latest, "ldap_method_id = ?", []any{am.GetPublicId()})
			require.NoError(err)
			require.NoError(latest.decrypt(testCtx, kmsWrapper))

			// make sure the password and its hmac are correct and that it uses
			// the newest key version id
			assert.NotEmpty(latest.KeyId)
			assert.Equal(newKeyVersion, latest.KeyId)
			assert.Equal(cc.GetCertificateKey(), latest.CertificateKey)
			assert.NotEqual(cc.GetCtCertificateKey(), latest.GetCtCertificateKey())
			assert.NotEmpty(latest.GetCertificateKeyHmac())
			assert.Equal(cc.GetCertificateKeyHmac(), latest.CertificateKeyHmac)
		})
	}
}
