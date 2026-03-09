// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package ldap

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/internal/auth/ldap/store"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestNewClientCertificate(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	_, testCertEncoded := TestGenerateCA(t, "localhost")
	_, testPrivKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	derPrivKey, err := x509.MarshalPKCS8PrivateKey(testPrivKey)
	require.NoError(t, err)

	tests := []struct {
		name            string
		ctx             context.Context
		authMethodId    string
		certKey         []byte
		cert            string
		want            *ClientCertificate
		wantErr         bool
		wantErrCode     errors.Code
		wantErrContains string
	}{
		{
			name:         "valid",
			ctx:          testCtx,
			authMethodId: "test-id",
			cert:         testCertEncoded,
			certKey:      derPrivKey,
			want: &ClientCertificate{
				ClientCertificate: &store.ClientCertificate{
					LdapMethodId:   "test-id",
					Certificate:    []byte(testCertEncoded),
					CertificateKey: derPrivKey,
				},
			},
		},
		{
			name:            "missing-auth-method-id",
			ctx:             testCtx,
			cert:            testCertEncoded,
			certKey:         derPrivKey,
			wantErr:         true,
			wantErrCode:     errors.InvalidParameter,
			wantErrContains: "missing auth method id",
		},
		{
			name:            "missing-cert",
			ctx:             testCtx,
			authMethodId:    "test-id",
			certKey:         derPrivKey,
			wantErr:         true,
			wantErrCode:     errors.InvalidParameter,
			wantErrContains: "missing certificate",
		},
		{
			name:            "missing-key",
			ctx:             testCtx,
			authMethodId:    "test-id",
			cert:            testCertEncoded,
			wantErr:         true,
			wantErrCode:     errors.InvalidParameter,
			wantErrContains: "missing key",
		},
		{
			name:            "invalid-key",
			ctx:             testCtx,
			authMethodId:    "test-id",
			cert:            testCertEncoded,
			certKey:         []byte("invalid-key"),
			wantErr:         true,
			wantErrCode:     errors.InvalidParameter,
			wantErrContains: "failed to parse key in PKCS #8, ASN.1 DER form",
		},
		{
			name:            "invalid-block",
			ctx:             testCtx,
			authMethodId:    "test-id",
			cert:            TestInvalidPem,
			certKey:         derPrivKey,
			wantErr:         true,
			wantErrCode:     errors.InvalidParameter,
			wantErrContains: "failed to parse certificate: invalid block",
		},
		{
			name:            "invalid-pem",
			ctx:             testCtx,
			authMethodId:    "test-id",
			cert:            "not-encoded",
			certKey:         derPrivKey,
			wantErr:         true,
			wantErrCode:     errors.InvalidParameter,
			wantErrContains: "failed to parse certificate: invalid PEM encoding",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := NewClientCertificate(tc.ctx, tc.authMethodId, tc.certKey, tc.cert)
			if tc.wantErr {
				require.Error(err)
				assert.Nil(got)
				if tc.wantErrCode != errors.Unknown {
					assert.True(errors.Match(errors.T(tc.wantErrCode), err))
				}
				if tc.wantErrContains != "" {
					assert.Contains(err.Error(), tc.wantErrContains)
				}
				return
			}
			require.NoError(err)
			assert.Equal(tc.want, got)
		})
	}
}

func TestClientCertificate_SetTableName(t *testing.T) {
	t.Parallel()
	defaultTableName := clientCertificateTableName
	tests := []struct {
		name      string
		setNameTo string
		want      string
	}{
		{
			name:      "new-name",
			setNameTo: "new-name",
			want:      "new-name",
		},
		{
			name:      "reset to default",
			setNameTo: "",
			want:      defaultTableName,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			def := allocClientCertificate()
			require.Equal(defaultTableName, def.TableName())
			m := allocClientCertificate()
			m.SetTableName(tt.setNameTo)
			assert.Equal(tt.want, m.TableName())
		})
	}
}

func TestClientCertificate_clone(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	t.Run("valid", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		_, pem := TestGenerateCA(t, "localhost")
		_, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(err)
		derEncodedKey, err := x509.MarshalPKCS8PrivateKey(privKey)
		require.NoError(err)

		cc, err := NewClientCertificate(testCtx, "test-id", derEncodedKey, pem)
		require.NoError(err)
		cp := cc.clone()
		assert.True(proto.Equal(cp.ClientCertificate, cc.ClientCertificate))
	})
	t.Run("not-equal", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		_, pem := TestGenerateCA(t, "localhost")
		_, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(err)
		derEncodedKey, err := x509.MarshalPKCS8PrivateKey(privKey)
		require.NoError(err)
		cc, err := NewClientCertificate(testCtx, "test-id", derEncodedKey, pem)
		require.NoError(err)

		_, pem2 := TestGenerateCA(t, "localhost")
		_, privKey2, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(err)
		derEncodedKey2, err := x509.MarshalPKCS8PrivateKey(privKey2)
		require.NoError(err)
		cc2, err := NewClientCertificate(testCtx, "test-id", derEncodedKey2, pem2)
		require.NoError(err)

		cp := cc.clone()
		assert.True(!proto.Equal(cp.ClientCertificate, cc2.ClientCertificate))
	})
}

func TestClientCertificate_encrypt_decrypt(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	testWrapper := db.TestWrapper(t)
	_, testCertEncoded := TestGenerateCA(t, "localhost")
	_, testPrivKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	derPrivKey, err := x509.MarshalPKCS8PrivateKey(testPrivKey)
	require.NoError(t, err)

	tests := []struct {
		name            string
		ctx             context.Context
		cipher          wrapping.Wrapper
		cc              *ClientCertificate
		wantErr         bool
		wantErrCode     errors.Code
		wantErrContains string
	}{
		{
			name:   "valid",
			ctx:    testCtx,
			cipher: testWrapper,
			cc: func() *ClientCertificate {
				testClientCert, err := NewClientCertificate(testCtx, "test-auth-method-id", derPrivKey, testCertEncoded)
				require.NoError(t, err)
				return testClientCert
			}(),
		},
		{
			name: "missing-cipher",
			ctx:  testCtx,
			cc: func() *ClientCertificate {
				testClientCert, err := NewClientCertificate(testCtx, "test-auth-method-id", derPrivKey, testCertEncoded)
				require.NoError(t, err)
				return testClientCert
			}(),
			wantErr:         true,
			wantErrCode:     errors.InvalidParameter,
			wantErrContains: "missing cipher",
		},
		{
			name: "encrypt-err",
			ctx:  testCtx,
			cipher: &kms.MockWrapper{
				Wrapper:    testWrapper,
				EncryptErr: fmt.Errorf("test encrypt error"),
			},
			cc: func() *ClientCertificate {
				testClientCert, err := NewClientCertificate(testCtx, "test-auth-method-id", derPrivKey, testCertEncoded)
				require.NoError(t, err)
				return testClientCert
			}(),
			wantErr:         true,
			wantErrCode:     errors.Encrypt,
			wantErrContains: "test encrypt error",
		},
		{
			name: "keyId-err",
			ctx:  testCtx,
			cipher: &kms.MockWrapper{
				Wrapper:  testWrapper,
				KeyIdErr: fmt.Errorf("test key id error"),
			},
			cc: func() *ClientCertificate {
				testClientCert, err := NewClientCertificate(testCtx, "test-auth-method-id", derPrivKey, testCertEncoded)
				require.NoError(t, err)
				return testClientCert
			}(),
			wantErr:         true,
			wantErrCode:     errors.Encrypt,
			wantErrContains: "test key id error",
		},
		{
			name: "keyBytes-err",
			ctx:  testCtx,
			cipher: &kms.MockWrapper{
				Wrapper: testWrapper,
				// KeyBytesErr: fmt.Errorf("test key bytes error"),
			},
			cc: func() *ClientCertificate {
				testClientCert, err := NewClientCertificate(testCtx, "test-auth-method-id", derPrivKey, testCertEncoded)
				require.NoError(t, err)
				return testClientCert
			}(),
			wantErr:         true,
			wantErrCode:     errors.Encrypt,
			wantErrContains: "failed to hmac client certificate",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			require.Empty(tc.cc.CtCertificateKey)
			require.Empty(tc.cc.CertificateKeyHmac)

			err := tc.cc.encrypt(tc.ctx, tc.cipher)
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
			assert.NotEmpty(tc.cc.GetCertificateKeyHmac())
			assert.NotEmpty(tc.cc.GetCtCertificateKey())

			origKey := make([]byte, len(tc.cc.CertificateKey))
			copy(origKey, tc.cc.CertificateKey)
			tc.cc.CertificateKey = nil
			require.NoError(tc.cc.decrypt(tc.ctx, tc.cipher))
			assert.NotEmpty(tc.cc.CertificateKey)
			assert.Equal(origKey, tc.cc.CertificateKey)
		})
	}
	t.Run("decrypt-missing-cipher", func(t *testing.T) {
		testBindCred, err := NewClientCertificate(testCtx, "test-id", derPrivKey, testCertEncoded)
		require.NoError(t, err)
		err = testBindCred.decrypt(testCtx, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "missing cipher")
	})
	t.Run("decrypt-err", func(t *testing.T) {
		w := &kms.MockWrapper{
			Wrapper:    testWrapper,
			DecryptErr: fmt.Errorf("test decrypt error"),
		}
		testBindCred, err := NewClientCertificate(testCtx, "test-id", derPrivKey, testCertEncoded)
		require.NoError(t, err)
		require.NoError(t, testBindCred.encrypt(testCtx, testWrapper))
		err = testBindCred.decrypt(testCtx, w)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "test decrypt error")
	})
}
