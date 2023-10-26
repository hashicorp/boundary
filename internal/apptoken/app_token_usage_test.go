// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package apptoken

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/apptoken/store"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestNewAppTokenUsage(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	const (
		testAppTokenId       = "appt_____test"
		testClientTcpAddress = "127.0.0.1"
		testRequestMethod    = "GET"
		testRequestPath      = "/test-resource"
	)

	tests := []struct {
		name             string
		appTokenId       string
		clientTcpAddress string
		requestMethod    string
		requestPath      string
		want             *AppTokenUsage
		wantErrContains  string
		wantErrMatch     *errors.Template
	}{
		{
			name:             "success",
			appTokenId:       testAppTokenId,
			clientTcpAddress: testClientTcpAddress,
			requestMethod:    testRequestMethod,
			requestPath:      testRequestPath,
			want: &AppTokenUsage{
				AppTokenUsage: &store.AppTokenUsage{
					AppTokenId:       testAppTokenId,
					ClientTcpAddress: testClientTcpAddress,
					RequestMethod:    testRequestMethod,
					RequestPath:      testRequestPath,
				},
			},
		},
		{
			name:             "missing-app-token-id",
			clientTcpAddress: testClientTcpAddress,
			requestMethod:    testRequestMethod,
			requestPath:      testRequestPath,
			wantErrContains:  "missing app token id",
			wantErrMatch:     errors.T(errors.InvalidParameter),
		},
		{
			name:            "missing-client-tcp-address",
			appTokenId:      testAppTokenId,
			requestMethod:   testRequestMethod,
			requestPath:     testRequestPath,
			wantErrContains: "missing cleint tcp address",
			wantErrMatch:    errors.T(errors.InvalidParameter),
		},
		{
			name:             "invalid-client-tcp-address",
			appTokenId:       testAppTokenId,
			requestMethod:    testRequestMethod,
			requestPath:      testRequestPath,
			clientTcpAddress: "255",
			wantErrContains:  "invalid client tcp address",
			wantErrMatch:     errors.T(errors.InvalidParameter),
		},
		{
			name:             "missing-request-method",
			appTokenId:       testAppTokenId,
			clientTcpAddress: testClientTcpAddress,
			requestPath:      testRequestPath,
			wantErrContains:  "missing request method",
			wantErrMatch:     errors.T(errors.InvalidParameter),
		},
		{
			name:             "missing-request-path",
			appTokenId:       testAppTokenId,
			clientTcpAddress: testClientTcpAddress,
			requestMethod:    testRequestMethod,
			wantErrContains:  "missing request path",
			wantErrMatch:     errors.T(errors.InvalidParameter),
		},
		{
			name:             "invalid-request-path",
			appTokenId:       testAppTokenId,
			clientTcpAddress: testClientTcpAddress,
			requestMethod:    testRequestMethod,
			requestPath:      "path",
			wantErrContains:  "invalid request path",
			wantErrMatch:     errors.T(errors.InvalidParameter),
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := NewAppTokenUsage(testCtx, tc.appTokenId, tc.clientTcpAddress, tc.requestMethod, tc.requestPath)
			if tc.wantErrContains != "" {
				require.Error(err)
				if tc.wantErrMatch != nil {
					assert.True(errors.Match(tc.wantErrMatch, err))
				}
				require.ErrorContains(err, tc.wantErrContains)
				return
			}
			require.NoError(err)
			assert.Equal(tc.want, got)
		})
	}
}

func TestAppTokenUsage_clone(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	const (
		testAppTokenId       = "appt_____test"
		testClientTcpAddress = "127.0.0.1"
		testRequestMethod    = "GET"
		testRequestPath      = "/test-resource"
	)

	t.Run("valid", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		orig, err := NewAppTokenUsage(testCtx, testAppTokenId, testClientTcpAddress, testRequestMethod, testRequestPath)
		require.NoError(err)
		cp := orig.clone()
		assert.True(proto.Equal(cp.AppTokenUsage, orig.AppTokenUsage))
	})
	t.Run("not-equal", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		orig, err := NewAppTokenUsage(testCtx, testAppTokenId, testClientTcpAddress, testRequestMethod, testRequestPath)
		require.NoError(err)
		orig2, err := NewAppTokenUsage(testCtx, testAppTokenId+"+2", testClientTcpAddress, testRequestMethod+"+2", testRequestPath+"+2")
		require.NoError(err)

		cp := orig.clone()
		assert.True(!proto.Equal(cp.AppTokenUsage, orig2.AppTokenUsage))
	})
}

func TestAppTokenUsage_SetTableName(t *testing.T) {
	t.Parallel()
	defaultTableName := appTokenUsageTableName
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
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			def := AllocAppTokenUsage()
			require.Equal(defaultTableName, def.TableName())
			m := AllocAppTokenUsage()
			m.SetTableName(tc.setNameTo)
			assert.Equal(tc.want, m.TableName())
		})
	}
}
