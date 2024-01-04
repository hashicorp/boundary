// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package proxy

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"math/big"
	mathrand "math/rand"
	"net"
	"testing"
	"time"

	"github.com/hashicorp/boundary/api/scopes"
	"github.com/hashicorp/boundary/api/targets"
	"github.com/mitchellh/copystructure"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	t.Parallel()

	sessionAuth := &targets.SessionAuthorizationData{
		SessionId: "s_1234567890",
		TargetId:  "ttcp_1234567890",
		Scope: &scopes.ScopeInfo{
			Id:            "p_1234567890",
			Type:          "project",
			ParentScopeId: "o_1234567890",
		},
		CreatedTime:     time.Now().Add(-time.Minute),
		Type:            "tcp",
		ConnectionLimit: 4,
		EndpointPort:    22,
		Expiration:      time.Now().Add(time.Minute),
		HostId:          "h_1234567890",
		Endpoint:        "localhost",
		WorkerInfo: []*targets.WorkerInfo{
			{
				Address: "localhost:9202",
			},
		},
	}
	l := &net.TCPListener{}

	pubKey, privKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	template := &x509.Certificate{
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		DNSNames:              []string{"s_1234567890"},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement | x509.KeyUsageCertSign,
		SerialNumber:          big.NewInt(mathrand.Int63()),
		NotBefore:             sessionAuth.CreatedTime.Add(-1 * time.Minute),
		NotAfter:              sessionAuth.Expiration,
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, pubKey, privKey)
	require.NoError(t, err)
	sessionAuth.Certificate = certBytes

	tc := []struct {
		name        string
		authzString string
		transformFn func(*targets.SessionAuthorizationData) *targets.SessionAuthorizationData
		opts        []Option
		errContains string
		badOpts     bool
	}{
		{
			name: "base",
			opts: []Option{WithSessionAuthorizationData(sessionAuth)},
		},
		{
			name:        "bad options",
			opts:        []Option{WithSessionAuthorizationData(nil)},
			errContains: "data passed to WithSessionAuthorizationData is nil",
		},
		{
			name:        "no authz string",
			errContains: "empty session authorization token and object",
		},
		{
			name:        "bad authz string",
			authzString: "bad",
			errContains: "error turning authz token into authorization data",
		},
		{
			name: "no workers",
			transformFn: func(in *targets.SessionAuthorizationData) *targets.SessionAuthorizationData {
				in.WorkerInfo = []*targets.WorkerInfo{}
				return in
			},
			opts:        []Option{WithSessionAuthorizationData(sessionAuth)},
			errContains: "no workers found in authorization data",
		},
		{
			name: "with listener",
			opts: []Option{WithSessionAuthorizationData(sessionAuth), WithListener(l)},
		},
	}
	for _, tt := range tc {
		t.Run(tt.name, func(t *testing.T) {
			require, assert := require.New(t), assert.New(t)
			cpRaw, err := copystructure.Copy(sessionAuth)
			require.NoError(err)
			cp := sessionAuth
			if tt.transformFn != nil {
				cp = tt.transformFn(cpRaw.(*targets.SessionAuthorizationData))
				tt.opts = append(tt.opts, WithSessionAuthorizationData(cp))
			}
			p, err := New(context.Background(), tt.authzString, tt.opts...)
			if tt.errContains != "" {
				require.ErrorContains(err, tt.errContains)
				return
			}
			require.NoError(err)
			assert.Len(p.tofuToken, 20)
			assert.Equal(p.sessionAuthzData, sessionAuth)
			assert.True(p.listenAddrPort.IsValid())

			opts, err := getOpts(tt.opts...)
			require.NoError(err)
			if opts.WithListener == nil {
				assert.EqualValues(getDefaultOptions().WithListenAddrPort.Addr(), p.listenAddrPort.Addr())
			} else {
				assert.Equal(p.listener.Load(), l)
			}
			assert.Equal(p.connectionsLeft.Load(), cp.ConnectionLimit)
			assert.Equal(p.ConnectionsLeft(), cp.ConnectionLimit)
			assert.Equal(p.createTime, sessionAuth.CreatedTime)
			assert.Equal(p.SessionCreatedTime(), sessionAuth.CreatedTime)
			assert.Equal(p.expiration, sessionAuth.Expiration)
			assert.Equal(p.SessionExpiration(), sessionAuth.Expiration)
			assert.NotNil(p.ctx)
			assert.NotNil(p.cancel)
			assert.NotNil(p.transport)
		})
	}
}
