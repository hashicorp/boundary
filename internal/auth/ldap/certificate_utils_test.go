// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package ldap

import (
	"context"
	"crypto/x509"
	"testing"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncodeCertificates(t *testing.T) {
	ctx := context.TODO()
	tests := []struct {
		name            string
		setup           func() ([]*x509.Certificate, []string)
		wantErr         bool
		wantErrCode     errors.Code
		wantErrContains string
	}{
		{
			name: "valid",
			setup: func() ([]*x509.Certificate, []string) {
				c1, p1 := TestGenerateCA(t, "localhost")
				c2, p2 := TestGenerateCA(t, "alice.com")

				return []*x509.Certificate{c1, c2}, []string{p1, p2}
			},
			wantErr: false,
		},
		{
			name: "empty-cert",
			setup: func() ([]*x509.Certificate, []string) {
				_, p1 := TestGenerateCA(t, "localhost")
				c2, p2 := TestGenerateCA(t, "alice.com")

				return []*x509.Certificate{nil, c2}, []string{p1, p2}
			},
			wantErr:         true,
			wantErrCode:     errors.InvalidParameter,
			wantErrContains: "nil cert",
		},
		{
			name: "nil-certs",
			setup: func() ([]*x509.Certificate, []string) {
				_, p1 := TestGenerateCA(t, "localhost")
				_, p2 := TestGenerateCA(t, "alice.com")

				return nil, []string{p1, p2}
			},
			wantErr:         true,
			wantErrCode:     errors.InvalidParameter,
			wantErrContains: "no certs provided",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			certs, pems := tc.setup()
			got, err := EncodeCertificates(ctx, certs...)
			if tc.wantErr {
				require.Error(err)
				assert.True(errors.Match(errors.T(tc.wantErrCode), err))
				if tc.wantErrContains != "" {
					assert.Contains(err.Error(), tc.wantErrContains)
				}
				return
			}
			require.NoError(err)
			assert.Equal(pems, got)
		})
	}
}

func TestParseCertificates(t *testing.T) {
	ctx := context.TODO()
	tests := []struct {
		name            string
		setup           func() ([]*x509.Certificate, []string)
		wantErr         bool
		wantErrCode     errors.Code
		wantErrContains string
	}{
		{
			name: "valid",
			setup: func() ([]*x509.Certificate, []string) {
				c1, p1 := TestGenerateCA(t, "localhost")
				c2, p2 := TestGenerateCA(t, "alice.com")

				return []*x509.Certificate{c1, c2}, []string{p1, p2}
			},
			wantErr: false,
		},
		{
			name: "empty-pem",
			setup: func() ([]*x509.Certificate, []string) {
				c1, _ := TestGenerateCA(t, "localhost")
				c2, p2 := TestGenerateCA(t, "alice.com")

				return []*x509.Certificate{c1, c2}, []string{"", p2}
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
		},
		{
			name: "nil-pem",
			setup: func() ([]*x509.Certificate, []string) {
				c1, _ := TestGenerateCA(t, "localhost")
				c2, _ := TestGenerateCA(t, "alice.com")

				return []*x509.Certificate{c1, c2}, nil
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
		},
		{
			name: "invalid-block",
			setup: func() ([]*x509.Certificate, []string) {
				c1, _ := TestGenerateCA(t, "localhost")
				return []*x509.Certificate{c1}, []string{TestInvalidPem}
			},
			wantErr:         true,
			wantErrCode:     errors.InvalidParameter,
			wantErrContains: "failed to parse certificate: invalid block",
		},
		{
			name: "invalid-pem",
			setup: func() ([]*x509.Certificate, []string) {
				c1, _ := TestGenerateCA(t, "localhost")
				return []*x509.Certificate{c1}, []string{"not-encoded"}
			},
			wantErr:         true,
			wantErrCode:     errors.InvalidParameter,
			wantErrContains: "failed to parse certificate: invalid PEM encoding",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			certs, pems := tc.setup()
			got, err := ParseCertificates(ctx, pems...)
			if tc.wantErr {
				require.Error(err)
				assert.True(errors.Match(errors.T(tc.wantErrCode), err))
				if tc.wantErrContains != "" {
					assert.Contains(err.Error(), tc.wantErrContains)
				}
				return
			}
			require.NoError(err)
			assert.Equal(certs, got)
		})
	}
}
