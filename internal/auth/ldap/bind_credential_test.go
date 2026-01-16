// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package ldap

import (
	"context"
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

func TestNewBindCredential(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	tests := []struct {
		name            string
		ctx             context.Context
		authMethodId    string
		dn              string
		password        []byte
		want            *BindCredential
		wantErr         bool
		wantErrCode     errors.Code
		wantErrContains string
	}{
		{
			name:         "valid",
			ctx:          testCtx,
			authMethodId: "test-id",
			dn:           "dn",
			password:     []byte("password"),
			want: &BindCredential{
				BindCredential: &store.BindCredential{
					LdapMethodId: "test-id",
					Dn:           "dn",
					Password:     []byte("password"),
				},
			},
		},
		{
			name:            "missing-auth-method-id",
			ctx:             testCtx,
			dn:              "dn",
			password:        []byte("password"),
			wantErr:         true,
			wantErrCode:     errors.InvalidParameter,
			wantErrContains: "missing auth method id",
		},
		{
			name:            "missing-dn",
			ctx:             testCtx,
			authMethodId:    "test-id",
			password:        []byte("password"),
			wantErr:         true,
			wantErrCode:     errors.InvalidParameter,
			wantErrContains: "missing dn",
		},
		{
			name:            "missing-password",
			ctx:             testCtx,
			authMethodId:    "test-id",
			dn:              "dn",
			wantErr:         true,
			wantErrCode:     errors.InvalidParameter,
			wantErrContains: "missing password",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := NewBindCredential(tc.ctx, tc.authMethodId, tc.dn, tc.password)
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

func TestBindCredential_SetTableName(t *testing.T) {
	t.Parallel()
	defaultTableName := bindCredentialTableName
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
			def := allocBindCredential()
			require.Equal(defaultTableName, def.TableName())
			m := allocBindCredential()
			m.SetTableName(tt.setNameTo)
			assert.Equal(tt.want, m.TableName())
		})
	}
}

func TestBindCredential_clone(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	t.Run("valid", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		bc, err := NewBindCredential(testCtx, "test-id", "dn", []byte("password"))
		require.NoError(err)
		cp := bc.clone()
		assert.True(proto.Equal(cp.BindCredential, bc.BindCredential))
	})
	t.Run("not-equal", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		bc, err := NewBindCredential(testCtx, "test-id", "dn2", []byte("password"))
		require.NoError(err)

		bc2, err := NewBindCredential(testCtx, "test-id", "dn", []byte("password2"))
		require.NoError(err)

		cp := bc.clone()
		assert.True(!proto.Equal(cp.BindCredential, bc2.BindCredential))
	})
}

func TestBindCredential_encrypt_decrypt(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	testWrapper := db.TestWrapper(t)
	tests := []struct {
		name            string
		ctx             context.Context
		cipher          wrapping.Wrapper
		bc              *BindCredential
		wantErr         bool
		wantErrCode     errors.Code
		wantErrContains string
	}{
		{
			name:   "valid",
			ctx:    testCtx,
			cipher: testWrapper,
			bc: func() *BindCredential {
				testBindCred, err := NewBindCredential(testCtx, "test-id", "dn", []byte("password"))
				require.NoError(t, err)
				return testBindCred
			}(),
		},
		{
			name: "missing-cipher",
			ctx:  testCtx,
			bc: func() *BindCredential {
				testBindCred, err := NewBindCredential(testCtx, "test-id", "dn", []byte("password"))
				require.NoError(t, err)
				return testBindCred
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
			bc: func() *BindCredential {
				testBindCred, err := NewBindCredential(testCtx, "test-id", "dn", []byte("password"))
				require.NoError(t, err)
				return testBindCred
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
			bc: func() *BindCredential {
				testBindCred, err := NewBindCredential(testCtx, "test-id", "dn", []byte("password"))
				require.NoError(t, err)
				return testBindCred
			}(),
			wantErr:         true,
			wantErrCode:     errors.Encrypt,
			wantErrContains: "test key id error",
		},
		{
			name: "unknown-wrapper-type-err",
			ctx:  testCtx,
			cipher: &kms.MockWrapper{
				Wrapper: testWrapper,
			},
			bc: func() *BindCredential {
				testBindCred, err := NewBindCredential(testCtx, "test-id", "dn", []byte("password"))
				require.NoError(t, err)
				return testBindCred
			}(),
			wantErr:         true,
			wantErrCode:     errors.Encrypt,
			wantErrContains: "failed to hmac password",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			require.Empty(tc.bc.CtPassword)
			require.Empty(tc.bc.PasswordHmac)

			err := tc.bc.encrypt(tc.ctx, tc.cipher)
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
			assert.NotEmpty(tc.bc.GetPasswordHmac())
			assert.NotEmpty(tc.bc.GetCtPassword())

			origPass := make([]byte, len(tc.bc.Password))
			copy(origPass, tc.bc.Password)
			tc.bc.Password = nil
			require.NoError(tc.bc.decrypt(tc.ctx, tc.cipher))
			assert.NotEmpty(tc.bc.Password)
			assert.Equal(origPass, tc.bc.Password)
		})
	}
	t.Run("decrypt-missing-cipher", func(t *testing.T) {
		testBindCred, err := NewBindCredential(testCtx, "test-id", "dn", []byte("password"))
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
		testBindCred, err := NewBindCredential(testCtx, "test-id", "dn", []byte("password"))
		require.NoError(t, err)
		require.NoError(t, testBindCred.encrypt(testCtx, testWrapper))
		err = testBindCred.decrypt(testCtx, w)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "test decrypt error")
	})
}
