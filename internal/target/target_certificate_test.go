// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package target

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"
	"time"

	talias "github.com/hashicorp/boundary/internal/alias/target"
	astore "github.com/hashicorp/boundary/internal/alias/target/store"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-kms-wrapping/v2/aead"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateTargetCert(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	privKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)

	aliasValue := "test-alias-value"
	alias := &talias.Alias{
		Alias: &astore.Alias{
			Value: aliasValue,
		},
	}

	tests := []struct {
		name            string
		privKey         *ecdsa.PrivateKey
		exp             time.Time
		opt             []Option
		wantErr         bool
		wantErrContains string
	}{
		{
			name:    "valid-target-proxy-cert",
			privKey: privKey,
			exp:     time.Now().Add(1 * time.Hour),
		},
		{
			name:    "valid-with-alias",
			privKey: privKey,
			exp:     time.Now().Add(1 * time.Hour),
			opt: []Option{
				WithAlias(alias),
			},
		},
		{
			name:            "invalid-expiration",
			privKey:         privKey,
			exp:             time.Now().Add(-1 * time.Hour),
			wantErr:         true,
			wantErrContains: "expiration time must be in the future",
		},
		{
			name:            "missing-key",
			exp:             time.Now().Add(1 * time.Hour),
			wantErr:         true,
			wantErrContains: "missing private key",
		},
		{
			name:            "missing-expiry",
			privKey:         privKey,
			wantErr:         true,
			wantErrContains: "missing expiry",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			got, err := generateTargetCert(ctx, tt.privKey, tt.exp, tt.opt...)

			if tt.wantErr {
				assert.Error(err)
				return
			}
			require.NoError(err)
			require.NotNil(got)

			pCert, err := x509.ParseCertificate(got)
			require.NoError(err)
			require.NotNil(pCert)

			require.Equal("localhost", pCert.Subject.CommonName)
			// Cert timestamps do not have ms resolution
			tt.exp = tt.exp.Truncate(time.Second)
			require.True(tt.exp.Equal(pCert.NotAfter))
			require.Contains(pCert.DNSNames, "localhost")
			if tt.opt != nil {
				opts := GetOpts(tt.opt...)
				require.Contains(pCert.DNSNames, opts.WithAlias.Value)
			}
		})
	}
}

func TestTargetProxyCertificate(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	tId := "test-target-id"

	tests := []struct {
		name            string
		opt             []Option
		wantErr         bool
		wantErrContains string
	}{
		{
			name: "valid-target-proxy-cert",
		},
		{
			name: "valid-with-options",
			opt: []Option{
				WithTargetId(tId),
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			gotCert, err := NewTargetProxyCertificate(ctx, tt.opt...)

			if tt.wantErr {
				assert.Error(err)
				return
			}
			require.NoError(err)
			require.NotNil(gotCert)

			if tt.opt != nil {
				assert.Equal(tId, gotCert.TargetId)
			}
		})
	}
}

func Test_encrypt_decrypt_TargetCert(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rootWrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, rootWrapper)
	org, proj := iam.TestScopes(t, iam.TestRepo(t, conn, rootWrapper))
	databaseWrapper, err := kmsCache.GetWrapper(ctx, org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)
	projDatabaseWrapper, err := kmsCache.GetWrapper(ctx, proj.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)

	proxyCert, err := NewTargetProxyCertificate(ctx)
	require.NoError(t, err)

	tests := []struct {
		name                string
		certKey             *TargetProxyCertificate
		encryptWrapper      wrapping.Wrapper
		wantEncryptErrMatch *errors.Template
		decryptWrapper      wrapping.Wrapper
		wantDecryptErrMatch *errors.Template
	}{
		{
			name:           "success",
			certKey:        proxyCert,
			encryptWrapper: databaseWrapper,
			decryptWrapper: databaseWrapper,
		},
		{
			name:                "encrypt-missing-wrapper",
			certKey:             proxyCert,
			wantEncryptErrMatch: errors.T(errors.InvalidParameter),
		},
		{
			name:                "encrypt-bad-wrapper",
			certKey:             proxyCert,
			encryptWrapper:      &aead.Wrapper{},
			wantEncryptErrMatch: errors.T(errors.Encrypt),
		},
		{
			name:                "encrypt-missing-wrapper",
			certKey:             proxyCert,
			encryptWrapper:      databaseWrapper,
			wantDecryptErrMatch: errors.T(errors.InvalidParameter),
		},
		{
			name:                "decrypt-bad-wrapper",
			certKey:             proxyCert,
			encryptWrapper:      databaseWrapper,
			decryptWrapper:      &aead.Wrapper{},
			wantDecryptErrMatch: errors.T(errors.Decrypt),
		},
		{
			name:                "decrypt-wrong-wrapper",
			certKey:             proxyCert,
			encryptWrapper:      databaseWrapper,
			decryptWrapper:      projDatabaseWrapper,
			wantDecryptErrMatch: errors.T(errors.Decrypt),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			encryptedCert := tt.certKey.Clone()
			err = encryptedCert.Encrypt(ctx, tt.encryptWrapper)
			if tt.wantEncryptErrMatch != nil {
				require.Error(err)
				assert.Truef(errors.Match(tt.wantEncryptErrMatch, err), "expected %q and got err: %+v", tt.wantEncryptErrMatch.Code, err)
				return
			}
			require.NoError(err)
			assert.NotEmpty(encryptedCert.PrivateKeyEncrypted)

			decryptedCert := encryptedCert.Clone()
			decryptedCert.PrivateKey = []byte("")
			err = decryptedCert.Decrypt(ctx, tt.decryptWrapper)
			if tt.wantDecryptErrMatch != nil {
				require.Error(err)
				assert.Truef(errors.Match(tt.wantDecryptErrMatch, err), "expected %q and got err: %+v", tt.wantDecryptErrMatch.Code, err)
				return
			}
			require.NoError(err)
			assert.Equal(tt.certKey.PrivateKey, decryptedCert.PrivateKey)
		})
	}
}

func TestTargetAliasProxyCertificate(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	tId := "test-target-id"
	tAId := "test-alias-id"
	aliasValue := "test-alias-value"
	alias := &talias.Alias{
		Alias: &astore.Alias{
			PublicId: tAId,
			Value:    aliasValue,
		},
	}

	tests := []struct {
		name            string
		targetId        string
		alias           *talias.Alias
		wantErr         bool
		wantErrContains string
	}{
		{
			name:     "valid-target-cert",
			targetId: tId,
			alias:    alias,
		},
		{
			name:            "missing-target-id",
			alias:           alias,
			wantErr:         true,
			wantErrContains: "missing target id",
		},
		{
			name:            "missing-alias",
			targetId:        tId,
			wantErr:         true,
			wantErrContains: "missing alias",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			gotCert, err := NewTargetAliasProxyCertificate(ctx, tt.targetId, tt.alias)

			if tt.wantErr {
				assert.Error(err)
				return
			}
			require.NoError(err)
			require.NotNil(gotCert)
			assert.Equal(tId, gotCert.TargetId)
			assert.Equal(tAId, gotCert.AliasId)
			assert.NotNil(gotCert.Certificate)
		})
	}
}

func Test_encrypt_decrypt_TargetAliasCert(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rootWrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, rootWrapper)
	org, proj := iam.TestScopes(t, iam.TestRepo(t, conn, rootWrapper))
	databaseWrapper, err := kmsCache.GetWrapper(ctx, org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)
	projDatabaseWrapper, err := kmsCache.GetWrapper(ctx, proj.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)

	tId := "test-target-id"
	tAId := "test-alias-id"
	aliasValue := "test-alias-value"
	alias := &talias.Alias{
		Alias: &astore.Alias{
			PublicId: tAId,
			Value:    aliasValue,
		},
	}

	proxyCert, err := NewTargetAliasProxyCertificate(ctx, tId, alias)
	require.NoError(t, err)

	tests := []struct {
		name                string
		certKey             *TargetAliasProxyCertificate
		encryptWrapper      wrapping.Wrapper
		wantEncryptErrMatch *errors.Template
		decryptWrapper      wrapping.Wrapper
		wantDecryptErrMatch *errors.Template
	}{
		{
			name:           "success",
			certKey:        proxyCert,
			encryptWrapper: databaseWrapper,
			decryptWrapper: databaseWrapper,
		},
		{
			name:                "encrypt-missing-wrapper",
			certKey:             proxyCert,
			wantEncryptErrMatch: errors.T(errors.InvalidParameter),
		},
		{
			name:                "encrypt-bad-wrapper",
			certKey:             proxyCert,
			encryptWrapper:      &aead.Wrapper{},
			wantEncryptErrMatch: errors.T(errors.Encrypt),
		},
		{
			name:                "encrypt-missing-wrapper",
			certKey:             proxyCert,
			encryptWrapper:      databaseWrapper,
			wantDecryptErrMatch: errors.T(errors.InvalidParameter),
		},
		{
			name:                "decrypt-bad-wrapper",
			certKey:             proxyCert,
			encryptWrapper:      databaseWrapper,
			decryptWrapper:      &aead.Wrapper{},
			wantDecryptErrMatch: errors.T(errors.Decrypt),
		},
		{
			name:                "decrypt-wrong-wrapper",
			certKey:             proxyCert,
			encryptWrapper:      databaseWrapper,
			decryptWrapper:      projDatabaseWrapper,
			wantDecryptErrMatch: errors.T(errors.Decrypt),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			encryptedCert := tt.certKey.Clone()
			err = encryptedCert.Encrypt(ctx, tt.encryptWrapper)
			if tt.wantEncryptErrMatch != nil {
				require.Error(err)
				assert.Truef(errors.Match(tt.wantEncryptErrMatch, err), "expected %q and got err: %+v", tt.wantEncryptErrMatch.Code, err)
				return
			}
			require.NoError(err)
			assert.NotEmpty(encryptedCert.PrivateKeyEncrypted)

			decryptedCert := encryptedCert.Clone()
			decryptedCert.PrivateKey = []byte("")
			err = decryptedCert.Decrypt(ctx, tt.decryptWrapper)
			if tt.wantDecryptErrMatch != nil {
				require.Error(err)
				assert.Truef(errors.Match(tt.wantDecryptErrMatch, err), "expected %q and got err: %+v", tt.wantDecryptErrMatch.Code, err)
				return
			}
			require.NoError(err)
			assert.Equal(tt.certKey.PrivateKey, decryptedCert.PrivateKey)
		})
	}
}

func TestTargetProxyCertToAndFromServerCert(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	cert, err := NewTargetProxyCertificate(ctx)
	require.NoError(t, err)
	require.NotNil(t, cert)
	serverCert, err := cert.ToServerCertificate(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, serverCert.CertificatePem)
	require.NotEmpty(t, serverCert.PrivateKeyPem)

	newCert := allocTargetProxyCertificate()
	err = newCert.fromServerCertificate(ctx, serverCert)
	require.NoError(t, err)
	require.Equal(t, cert.Certificate, newCert.Certificate)
}

func TestTargetAliasProxyCertToAndFromServerCert(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	tId := "test-target-id"
	tAId := "test-alias-id"
	aliasValue := "test-alias-value"
	alias := &talias.Alias{
		Alias: &astore.Alias{
			PublicId: tAId,
			Value:    aliasValue,
		},
	}

	cert, err := NewTargetAliasProxyCertificate(ctx, tId, alias)
	require.NoError(t, err)
	require.NotNil(t, cert)
	serverCert, err := cert.ToServerCertificate(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, serverCert.CertificatePem)
	require.NotEmpty(t, serverCert.PrivateKeyPem)

	newCert := allocTargetAliasProxyCertificate()
	err = newCert.fromServerCertificate(ctx, serverCert)
	require.NoError(t, err)
	require.Equal(t, cert.Certificate, newCert.Certificate)
}
