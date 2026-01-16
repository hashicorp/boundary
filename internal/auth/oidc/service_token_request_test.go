// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package oidc

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/auth/oidc/request"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/mr-tron/base58"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func Test_TokenRequest(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	rootWrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, rootWrapper)

	iamRepo := iam.TestRepo(t, conn, rootWrapper)
	org, _ := iam.TestScopes(t, iamRepo)
	orgDatabaseWrapper, err := kmsCache.GetWrapper(ctx, org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)

	atRepoFn := func() (*authtoken.Repository, error) {
		r, err := authtoken.NewRepository(ctx, rw, rw, kmsCache)
		require.NoError(t, err)
		return r, nil
	}
	testAtRepo, err := authtoken.NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(t, err)

	// a reusable test authmethod for the unit tests
	testAuthMethod := TestAuthMethod(t, conn, orgDatabaseWrapper, org.PublicId, ActivePublicState,
		"alice-rp", "fido",
		WithSigningAlgs(Alg(RS256)),
		WithIssuer(TestConvertToUrls(t, "https://alice.com")[0]),
		WithApiUrl(TestConvertToUrls(t, "https://alice.com/callback")[0]))

	testAcct := TestAccount(t, conn, testAuthMethod, "alice")
	testUser := iam.TestUser(t, iamRepo, org.PublicId, iam.WithAccountIds(testAcct.PublicId))

	testRequestWrapper, err := requestWrappingWrapper(ctx, kmsCache, testAuthMethod.ScopeId, testAuthMethod.PublicId)
	require.NoError(t, err)

	tests := []struct {
		name            string
		kms             *kms.Kms
		atRepoFn        AuthTokenRepoFactory
		authMethodId    string
		tokenRequest    string
		wantNil         bool
		wantErrMatch    *errors.Template
		wantErrContains string
	}{
		{
			name:            "missing-kms",
			atRepoFn:        atRepoFn,
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing kms",
		},
		{
			name:            "missing-repoFn",
			kms:             kmsCache,
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing auth token repo function",
		},
		{
			name:            "bad-wrapper",
			kms:             kmsCache,
			atRepoFn:        atRepoFn,
			authMethodId:    testAuthMethod.PublicId,
			tokenRequest:    "bad-wrapper",
			wantErrMatch:    errors.T(errors.Unknown),
			wantErrContains: "unable to decode message",
		},
		{
			name:         "missing-wrapper-scope-id",
			kms:          kmsCache,
			atRepoFn:     atRepoFn,
			authMethodId: testAuthMethod.PublicId,
			tokenRequest: func() string {
				w := request.Wrapper{
					AuthMethodId: testAuthMethod.PublicId,
				}
				b, err := proto.Marshal(&w)
				require.NoError(t, err)
				return base58.Encode(b)
			}(),
			wantErrMatch:    errors.T(errors.Unknown),
			wantErrContains: "missing scope id",
		},
		{
			name:         "missing-auth-method-id",
			kms:          kmsCache,
			atRepoFn:     atRepoFn,
			authMethodId: "",
			tokenRequest: func() string {
				tokenPublicId, err := authtoken.NewAuthTokenId(ctx)
				require.NoError(t, err)
				TestPendingToken(t, testAtRepo, testUser, testAcct, tokenPublicId)
				return TestTokenRequestId(t, testAuthMethod, kmsCache, 200*time.Second, tokenPublicId)
			}(),
			wantErrMatch:    errors.T(errors.Unknown),
			wantErrContains: "missing auth method id",
		},
		{
			name:         "missing-wrapper-auth-method-id",
			kms:          kmsCache,
			atRepoFn:     atRepoFn,
			authMethodId: testAuthMethod.PublicId,
			tokenRequest: func() string {
				w := request.Wrapper{
					ScopeId: testAuthMethod.ScopeId,
				}
				b, err := proto.Marshal(&w)
				require.NoError(t, err)
				return base58.Encode(b)
			}(),
			wantErrMatch:    errors.T(errors.Unknown),
			wantErrContains: "missing auth method id",
		},
		{
			name:         "dek-not-found",
			kms:          kms.TestKms(t, conn, db.TestWrapper(t)),
			atRepoFn:     atRepoFn,
			authMethodId: testAuthMethod.PublicId,
			tokenRequest: func() string {
				tokenPublicId, err := authtoken.NewAuthTokenId(ctx)
				require.NoError(t, err)
				TestPendingToken(t, testAtRepo, testUser, testAcct, tokenPublicId)
				return TestTokenRequestId(t, testAuthMethod, kmsCache, 200*time.Second, tokenPublicId)
			}(),
			wantErrMatch:    errors.T(errors.Unknown),
			wantErrContains: "unable to get oidc wrapper",
		},
		{
			name:         "expired",
			kms:          kmsCache,
			atRepoFn:     atRepoFn,
			authMethodId: testAuthMethod.PublicId,
			tokenRequest: func() string {
				tokenPublicId, err := authtoken.NewAuthTokenId(ctx)
				require.NoError(t, err)
				TestPendingToken(t, testAtRepo, testUser, testAcct, tokenPublicId)
				return TestTokenRequestId(t, testAuthMethod, kmsCache, 0, tokenPublicId)
			}(),
			wantErrMatch:    errors.T(errors.Unknown),
			wantErrContains: "request token id has expired",
		},
		{
			name: "atRepoFn-error",
			kms:  kmsCache,
			atRepoFn: func() (*authtoken.Repository, error) {
				return nil, errors.New(ctx, errors.Unknown, "test op", "atRepoFn-error", errors.WithoutEvent())
			},
			authMethodId: testAuthMethod.PublicId,
			tokenRequest: func() string {
				tokenPublicId, err := authtoken.NewAuthTokenId(ctx)
				require.NoError(t, err)
				TestPendingToken(t, testAtRepo, testUser, testAcct, tokenPublicId)
				return TestTokenRequestId(t, testAuthMethod, kmsCache, 200*time.Second, tokenPublicId)
			}(),
			wantErrMatch:    errors.T(errors.Unknown),
			wantErrContains: "atRepoFn-error",
		},
		{
			name:         "error-unmarshal",
			kms:          kmsCache,
			atRepoFn:     atRepoFn,
			authMethodId: testAuthMethod.PublicId,
			tokenRequest: func() string {
				blobInfo, err := testRequestWrapper.Encrypt(ctx, []byte("not-valid-request-token"), wrapping.WithAad([]byte(fmt.Sprintf("%s%s", testAuthMethod.PublicId, testAuthMethod.ScopeId))))
				require.NoError(t, err)
				marshaledBlob, err := proto.Marshal(blobInfo)
				require.NoError(t, err)
				keyId, err := testRequestWrapper.KeyId(ctx)
				require.NoError(t, err)
				w := request.Wrapper{
					ScopeId:      testAuthMethod.ScopeId,
					AuthMethodId: testAuthMethod.PublicId,
					WrapperKeyId: keyId,
					Ct:           marshaledBlob,
				}
				require.NoError(t, err)
				b, err := proto.Marshal(&w)
				require.NoError(t, err)
				return base58.Encode(b)
			}(),
			wantErrMatch:    errors.T(errors.Unknown),
			wantErrContains: "unable to unmarshal request token",
		},
		{
			name:         "error-missing-exp",
			kms:          kmsCache,
			atRepoFn:     atRepoFn,
			authMethodId: testAuthMethod.PublicId,
			tokenRequest: func() string {
				tokenPublicId, err := authtoken.NewAuthTokenId(ctx)
				require.NoError(t, err)
				reqTk := request.Token{
					RequestId: tokenPublicId,
				}
				marshaledReqTk, err := proto.Marshal(&reqTk)
				require.NoError(t, err)
				blobInfo, err := testRequestWrapper.Encrypt(ctx, marshaledReqTk, wrapping.WithAad([]byte(fmt.Sprintf("%s%s", testAuthMethod.PublicId, testAuthMethod.ScopeId))))
				require.NoError(t, err)
				marshaledBlob, err := proto.Marshal(blobInfo)
				require.NoError(t, err)
				keyId, err := testRequestWrapper.KeyId(ctx)
				require.NoError(t, err)
				w := request.Wrapper{
					ScopeId:      testAuthMethod.ScopeId,
					AuthMethodId: testAuthMethod.PublicId,
					WrapperKeyId: keyId,
					Ct:           marshaledBlob,
				}
				require.NoError(t, err)
				b, err := proto.Marshal(&w)
				require.NoError(t, err)
				return base58.Encode(b)
			}(),
			wantErrMatch:    errors.T(errors.Unknown),
			wantErrContains: "missing request token id expiration",
		},
		{
			name:         "error-missing-request-id",
			kms:          kmsCache,
			atRepoFn:     atRepoFn,
			authMethodId: testAuthMethod.PublicId,
			tokenRequest: func() string {
				exp := timestamppb.New(time.Now().Add(AttemptExpiration).Truncate(time.Second))
				reqTk := request.Token{
					ExpirationTime: &timestamp.Timestamp{Timestamp: exp},
				}
				marshaledReqTk, err := proto.Marshal(&reqTk)
				require.NoError(t, err)
				blobInfo, err := testRequestWrapper.Encrypt(ctx, marshaledReqTk, wrapping.WithAad([]byte(fmt.Sprintf("%s%s", testAuthMethod.PublicId, testAuthMethod.ScopeId))))
				require.NoError(t, err)
				marshaledBlob, err := proto.Marshal(blobInfo)
				require.NoError(t, err)
				keyId, err := testRequestWrapper.KeyId(ctx)
				require.NoError(t, err)
				w := request.Wrapper{
					ScopeId:      testAuthMethod.ScopeId,
					AuthMethodId: testAuthMethod.PublicId,
					WrapperKeyId: keyId,
					Ct:           marshaledBlob,
				}
				require.NoError(t, err)
				b, err := proto.Marshal(&w)
				require.NoError(t, err)
				return base58.Encode(b)
			}(),
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing token request id",
		},
		{
			name:         "error-issuing-token-forbidden-code",
			kms:          kmsCache,
			atRepoFn:     atRepoFn,
			authMethodId: testAuthMethod.PublicId,
			tokenRequest: func() string {
				exp := timestamppb.New(time.Now().Add(AttemptExpiration).Truncate(time.Second))
				reqTk := request.Token{
					RequestId:      "not-a-valid-id",
					ExpirationTime: &timestamp.Timestamp{Timestamp: exp},
				}
				marshaledReqTk, err := proto.Marshal(&reqTk)
				require.NoError(t, err)
				blobInfo, err := testRequestWrapper.Encrypt(ctx, marshaledReqTk, wrapping.WithAad([]byte(fmt.Sprintf("%s%s", testAuthMethod.PublicId, testAuthMethod.ScopeId))))
				require.NoError(t, err)
				marshaledBlob, err := proto.Marshal(blobInfo)
				require.NoError(t, err)
				keyId, err := testRequestWrapper.KeyId(ctx)
				require.NoError(t, err)
				w := request.Wrapper{
					ScopeId:      testAuthMethod.ScopeId,
					AuthMethodId: testAuthMethod.PublicId,
					WrapperKeyId: keyId,
					Ct:           marshaledBlob,
				}
				require.NoError(t, err)
				b, err := proto.Marshal(&w)
				require.NoError(t, err)
				return base58.Encode(b)
			}(),
			wantNil: true,
		},
		{
			name:         "mismatched-auth-method-id",
			kms:          kmsCache,
			atRepoFn:     atRepoFn,
			authMethodId: "not-a-match",
			tokenRequest: func() string {
				tokenPublicId, err := authtoken.NewAuthTokenId(ctx)
				require.NoError(t, err)
				TestPendingToken(t, testAtRepo, testUser, testAcct, tokenPublicId)
				return TestTokenRequestId(t, testAuthMethod, kmsCache, 200*time.Second, tokenPublicId)
			}(),
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "auth method id does not match request wrapper auth method id",
		},
		{
			name:         "success",
			kms:          kmsCache,
			atRepoFn:     atRepoFn,
			authMethodId: testAuthMethod.PublicId,
			tokenRequest: func() string {
				tokenPublicId, err := authtoken.NewAuthTokenId(ctx)
				require.NoError(t, err)
				TestPendingToken(t, testAtRepo, testUser, testAcct, tokenPublicId)
				return TestTokenRequestId(t, testAuthMethod, kmsCache, 200*time.Second, tokenPublicId)
			}(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			gotTk, err := TokenRequest(ctx, tt.kms, tt.atRepoFn, tt.authMethodId, tt.tokenRequest)
			if tt.wantErrMatch != nil {
				require.Error(err)
				assert.Truef(errors.Match(tt.wantErrMatch, err), "wanted %q and got: %+v", tt.wantErrMatch.Code, err)
				if tt.wantErrContains != "" {
					assert.Contains(err.Error(), tt.wantErrContains)
				}
				return
			}
			require.NoError(err)
			if tt.wantNil {
				assert.Empty(gotTk)
			} else {
				assert.NotEmpty(gotTk)
			}
		})
	}
}
