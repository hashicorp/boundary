// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package ldap

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/auth/ldap/store"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestNewCertificate(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	_, testCertEncoded := TestGenerateCA(t, "localhost")
	tests := []struct {
		name            string
		ctx             context.Context
		authMethodId    string
		certPem         string
		want            *Certificate
		wantErr         bool
		wantErrCode     errors.Code
		wantErrContains string
	}{
		{
			name:         "valid",
			ctx:          testCtx,
			authMethodId: "test-id",
			certPem:      testCertEncoded,
			want: &Certificate{
				Certificate: &store.Certificate{
					LdapMethodId: "test-id",
					Cert:         testCertEncoded,
				},
			},
		},
		{
			name:            "missing-auth-method-id",
			ctx:             testCtx,
			certPem:         testCertEncoded,
			wantErr:         true,
			wantErrCode:     errors.InvalidParameter,
			wantErrContains: "missing ldap auth method id",
		},
		{
			name:            "missing-cert",
			ctx:             testCtx,
			authMethodId:    "test-id",
			wantErr:         true,
			wantErrCode:     errors.InvalidParameter,
			wantErrContains: "missing certificate",
		},
		{
			name:            "invalid-cert",
			ctx:             testCtx,
			authMethodId:    "test-id",
			certPem:         "not-a-cert",
			wantErr:         true,
			wantErrCode:     errors.InvalidParameter,
			wantErrContains: "failed to parse certificate: invalid PEM encoding",
		},
		{
			name:            "invalid-block",
			ctx:             testCtx,
			authMethodId:    "test-id",
			certPem:         TestInvalidPem,
			wantErr:         true,
			wantErrCode:     errors.InvalidParameter,
			wantErrContains: "failed to parse certificate: invalid block",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			gotCert, err := NewCertificate(tc.ctx, tc.authMethodId, tc.certPem)
			if tc.wantErr {
				require.Error(err)
				assert.Nil(gotCert)
				if tc.wantErrCode != errors.Unknown {
					assert.True(errors.Match(errors.T(tc.wantErrCode), err))
				}
				if tc.wantErrContains != "" {
					assert.Contains(err.Error(), tc.wantErrContains)
				}
				return
			}
		})
	}
}

func TestCertificate_SetTableName(t *testing.T) {
	t.Parallel()
	defaultTableName := certificateTableName
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
			def := allocCertificate()
			require.Equal(defaultTableName, def.TableName())
			m := allocCertificate()
			m.SetTableName(tt.setNameTo)
			assert.Equal(tt.want, m.TableName())
		})
	}
}

func TestCertificate_clone(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	t.Run("valid", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		_, testCertEncoded := TestGenerateCA(t, "localhost")
		c, err := NewCertificate(testCtx, "test-id", testCertEncoded)
		require.NoError(err)
		cp := c.clone()
		assert.True(proto.Equal(cp.Certificate, c.Certificate))
	})
	t.Run("not-equal", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		_, testCertEncoded := TestGenerateCA(t, "localhost")
		c, err := NewCertificate(testCtx, "test-id", testCertEncoded)
		require.NoError(err)

		_, testCertEncoded2 := TestGenerateCA(t, "alice.com")
		c2, err := NewCertificate(testCtx, "test-id", testCertEncoded2)
		require.NoError(err)

		cp := c.clone()
		assert.True(!proto.Equal(cp.Certificate, c2.Certificate))
	})
}
