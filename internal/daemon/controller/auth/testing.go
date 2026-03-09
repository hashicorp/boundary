// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package auth

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/daemon/controller/common"
	"github.com/hashicorp/boundary/internal/db"
	authpb "github.com/hashicorp/boundary/internal/gen/controller/auth"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/requests"
	"github.com/hashicorp/boundary/internal/server"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/stretchr/testify/require"
)

// DisabledAuthTestContext is meant for testing, and uses a context that has
// auth checking entirely disabled. Supported options: WithScopeId an WithUserId
// are used directly; WithKms is passed through into the verifier context.
func DisabledAuthTestContext(iamRepoFn common.IamRepoFactory, scopeId string, opt ...Option) context.Context {
	reqInfo := authpb.RequestInfo{DisableAuthEntirely: true}
	opts := getOpts(opt...)
	reqInfo.ScopeIdOverride = opts.withScopeId
	if reqInfo.ScopeIdOverride == "" {
		reqInfo.ScopeIdOverride = scopeId
	}
	reqInfo.UserIdOverride = opts.withUserId
	if reqInfo.UserIdOverride == "" {
		reqInfo.UserIdOverride = globals.AnyAuthenticatedUserId
	}
	reqInfo.Actions = opts.withActions
	requestContext := context.WithValue(context.Background(), requests.ContextRequestInformationKey, &requests.RequestContext{})
	return NewVerifierContext(requestContext, iamRepoFn, nil, nil, opts.withKms, &reqInfo)
}

// TestAuthContextFromToken creates an auth context with provided token
// This is used in conjunction with TestAuthTokenWithRoles which creates a test token
func TestAuthContextFromToken(t *testing.T, conn *db.DB, wrap wrapping.Wrapper, token *authtoken.AuthToken, iamRepo *iam.Repository) context.Context {
	t.Helper()
	ctx := context.Background()
	rw := db.New(conn)
	kmsCache := kms.TestKms(t, conn, wrap)
	atRepo, err := authtoken.NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(t, err)
	serversRepoFn := func() (*server.Repository, error) {
		return server.NewRepository(ctx, rw, rw, kmsCache)
	}
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	atRepoFn := func() (*authtoken.Repository, error) {
		return atRepo, nil
	}
	fullGrantAuthCtx := NewVerifierContext(requests.NewRequestContext(ctx, requests.WithUserId(token.GetIamUserId())),
		iamRepoFn, atRepoFn, serversRepoFn, kmsCache, &authpb.RequestInfo{
			PublicId:    token.PublicId,
			Token:       token.GetToken(),
			TokenFormat: uint32(AuthTokenTypeBearer),
		})
	return fullGrantAuthCtx
}
