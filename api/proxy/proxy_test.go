// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package proxy

import (
	"context"
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

	tc := []struct {
		name        string
		authzString string
		transformFn func(*targets.SessionAuthorizationData) *targets.SessionAuthorizationData
		errContains string
	}{
		{
			name: "base",
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
			errContains: "no workers found in authorization data",
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
			}
			opts := []Option{WithListener(l)}
			if tt.authzString == "" {
				opts = append(opts, WithSessionAuthorizationData(cp))
			}
			p, err := New(context.Background(), tt.authzString, opts...)
			if tt.errContains != "" {
				require.ErrorContains(err, tt.errContains)
				return
			}
			require.NoError(err)
			assert.Equal(p.listener.Load(), l)
			assert.Len(p.tofuToken, 20)
			assert.Equal(p.sessionAuthzData, sessionAuth)
			assert.Equal(p.connectionsLeft.Load(), cp.ConnectionLimit)
			assert.Equal(p.createTime, sessionAuth.CreatedTime)
			assert.Equal(p.expiration, sessionAuth.Expiration)
			assert.NotNil(p.ctx)
			assert.NotNil(p.cancel)
			assert.NotNil(p.transport)
		})
	}
}
