// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package oidc

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
		name      string
		setup     func() ([]*x509.Certificate, []string)
		wantErr   bool
		wantIsErr errors.Code
	}{
		{
			name: "valid",
			setup: func() ([]*x509.Certificate, []string) {
				c1, p1 := testGenerateCA(t, "localhost")
				c2, p2 := testGenerateCA(t, "alice.com")

				return []*x509.Certificate{c1, c2}, []string{p1, p2}
			},
			wantErr: false,
		},
		{
			name: "empty-cert",
			setup: func() ([]*x509.Certificate, []string) {
				_, p1 := testGenerateCA(t, "localhost")
				c2, p2 := testGenerateCA(t, "alice.com")

				return []*x509.Certificate{nil, c2}, []string{p1, p2}
			},
			wantErr:   true,
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "nil-certs",
			setup: func() ([]*x509.Certificate, []string) {
				_, p1 := testGenerateCA(t, "localhost")
				_, p2 := testGenerateCA(t, "alice.com")

				return nil, []string{p1, p2}
			},
			wantErr:   true,
			wantIsErr: errors.InvalidParameter,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			certs, pems := tt.setup()
			got, err := EncodeCertificates(ctx, certs...)
			if tt.wantErr {
				require.Error(err)
				assert.True(errors.Match(errors.T(tt.wantIsErr), err))
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
		name      string
		setup     func() ([]*x509.Certificate, []string)
		wantErr   bool
		wantIsErr errors.Code
	}{
		{
			name: "valid",
			setup: func() ([]*x509.Certificate, []string) {
				c1, p1 := testGenerateCA(t, "localhost")
				c2, p2 := testGenerateCA(t, "alice.com")

				return []*x509.Certificate{c1, c2}, []string{p1, p2}
			},
			wantErr: false,
		},
		{
			name: "empty-pem",
			setup: func() ([]*x509.Certificate, []string) {
				c1, _ := testGenerateCA(t, "localhost")
				c2, p2 := testGenerateCA(t, "alice.com")

				return []*x509.Certificate{c1, c2}, []string{"", p2}
			},
			wantErr:   true,
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "nil-pem",
			setup: func() ([]*x509.Certificate, []string) {
				c1, _ := testGenerateCA(t, "localhost")
				c2, _ := testGenerateCA(t, "alice.com")

				return []*x509.Certificate{c1, c2}, nil
			},
			wantErr:   true,
			wantIsErr: errors.InvalidParameter,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			certs, pems := tt.setup()
			got, err := ParseCertificates(ctx, pems...)
			if tt.wantErr {
				require.Error(err)
				assert.True(errors.Match(errors.T(tt.wantIsErr), err))
				return
			}
			require.NoError(err)
			assert.Equal(certs, got)
		})
	}
}
