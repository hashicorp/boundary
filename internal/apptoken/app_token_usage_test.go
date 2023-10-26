// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package apptoken

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/apptoken/store"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestNewAppTokenUsage(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	testTime := time.Now().Truncate(time.Second)
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
		createdTime      time.Time
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
			createdTime:      testTime,
			want: &AppTokenUsage{
				AppTokenUsage: &store.AppTokenUsage{
					AppTokenId:       testAppTokenId,
					ClientTcpAddress: testClientTcpAddress,
					RequestMethod:    testRequestMethod,
					RequestPath:      testRequestPath,
					CreateTime:       &timestamp.Timestamp{Timestamp: timestamppb.New(testTime)},
				},
			},
		},
		{
			name:             "missing-app-token-id",
			clientTcpAddress: testClientTcpAddress,
			requestMethod:    testRequestMethod,
			requestPath:      testRequestPath,
			createdTime:      testTime,
			wantErrContains:  "missing  app token id",
			wantErrMatch:     errors.T(errors.InvalidParameter),
		},
		{
			name:            "missing-client-tcp-address",
			appTokenId:      testAppTokenId,
			requestMethod:   testRequestMethod,
			requestPath:     testRequestPath,
			createdTime:     testTime,
			wantErrContains: "missing created by cleint tcp address",
			wantErrMatch:    errors.T(errors.InvalidParameter),
		},
		{
			name:             "missing-created-time",
			appTokenId:       testAppTokenId,
			clientTcpAddress: testClientTcpAddress,
			requestMethod:    testRequestMethod,
			requestPath:      testRequestPath,
			wantErrContains:  "missing created time",
			wantErrMatch:     errors.T(errors.InvalidParameter),
		},
		{
			name:             "missing-request-method",
			appTokenId:       testAppTokenId,
			clientTcpAddress: testClientTcpAddress,
			createdTime:      testTime,
			requestPath:      testRequestPath,
			wantErrContains:  "missing request method",
			wantErrMatch:     errors.T(errors.InvalidParameter),
		},
		{
			name:             "missing-request-path",
			appTokenId:       testAppTokenId,
			clientTcpAddress: testClientTcpAddress,
			createdTime:      testTime,
			requestMethod:    testRequestMethod,
			wantErrContains:  "missing request path",
			wantErrMatch:     errors.T(errors.InvalidParameter),
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := NewAppTokenUsage(testCtx, tc.appTokenId, tc.clientTcpAddress, tc.requestMethod, tc.requestPath, tc.createdTime)
			if tc.wantErrContains != "" {
				require.Error(err)
				if tc.wantErrMatch != nil {
					assert.True(errors.Match(tc.wantErrMatch, err))
				}
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
	testTime := time.Now().Truncate(time.Second)
	const (
		testAppTokenId       = "appt_____test"
		testClientTcpAddress = "127.0.0.1"
		testRequestMethod    = "GET"
		testRequestPath      = "/test-resource"
	)

	t.Run("valid", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		orig, err := NewAppTokenUsage(testCtx, testAppTokenId, testClientTcpAddress, testRequestMethod, testRequestPath, testTime)
		require.NoError(err)
		cp := orig.clone()
		assert.True(proto.Equal(cp.AppTokenUsage, orig.AppTokenUsage))
	})
	t.Run("not-equal", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		orig, err := NewAppTokenUsage(testCtx, testAppTokenId, testClientTcpAddress, testRequestMethod, testRequestPath, testTime)
		require.NoError(err)
		orig2, err := NewAppTokenUsage(testCtx, testAppTokenId+"+2", testClientTcpAddress+"+2", testRequestMethod+"+2", testRequestPath+"+2", testTime.Add(2*time.Hour))
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
