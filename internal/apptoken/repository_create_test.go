// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package apptoken_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/internal/apptoken"
	"github.com/hashicorp/boundary/internal/apptoken/store"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"
)

func Test_CreateAppToken(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	testConn, _ := db.TestSetup(t, "postgres")
	testRw := db.New(testConn)
	testRootWrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, testConn, testRootWrapper)
	testIamRepo := iam.TestRepo(t, testConn, testRootWrapper)
	testOrg, _ := iam.TestScopes(t, testIamRepo)
	testRepo, err := apptoken.NewRepository(testCtx, testRw, testRw, testKms, testIamRepo)
	testUser := iam.TestUser(t, testIamRepo, testOrg.GetPublicId())
	require.NoError(t, err)

	testUserHistoryId, err := testRepo.ResolveUserHistoryId(testCtx, testUser.GetPublicId())
	require.NoError(t, err)

	testExp := time.Now().Add(10 * time.Minute)

	tests := []struct {
		name            string
		scopeId         string
		expTime         time.Time
		createdBy       string
		grants          []string
		opts            []apptoken.Option
		wantToken       *apptoken.AppToken
		wantGrants      []*apptoken.AppTokenGrant
		wantErrContains string
		wantErrMatch    *errors.Template
	}{
		{
			name:      "success-with-options",
			scopeId:   testOrg.GetPublicId(),
			expTime:   testExp,
			createdBy: testUserHistoryId,
			grants: []string{
				"id=*;type=*;actions=read",
			},
			opts: []apptoken.Option{
				apptoken.WithName(testCtx, "test-apptoken"),
				apptoken.WithDescription(testCtx, "test-description"),
				apptoken.WithExpirationInterval(testCtx, 60),
			},
			wantToken: &apptoken.AppToken{
				AppToken: &store.AppToken{
					CreatedBy:                      testUserHistoryId,
					ExpirationTime:                 timestamp.New(testExp.Truncate(time.Second)),
					Name:                           "test-apptoken",
					Description:                    "test-description",
					ScopeId:                        testOrg.GetPublicId(),
					ExpirationIntervalInMaxSeconds: 60,
				},
			},
			wantGrants: []*apptoken.AppTokenGrant{
				{
					AppTokenGrant: &store.AppTokenGrant{},
				},
			},
		},
		{
			name:      "missing-scope-id",
			scopeId:   "",
			expTime:   testExp,
			createdBy: testUserHistoryId,
			grants: []string{
				"id=*;type=*;actions=read",
			},
			opts: []apptoken.Option{
				apptoken.WithName(testCtx, "test-apptoken"),
				apptoken.WithDescription(testCtx, "test-description"),
			},
			wantErrContains: "missing scope id",
		},
		{
			name:      "missing-created-by-user-id",
			scopeId:   testOrg.GetPublicId(),
			expTime:   testExp,
			createdBy: "",
			grants: []string{
				"id=*;type=*;actions=read",
			},
			opts: []apptoken.Option{
				apptoken.WithName(testCtx, "test-apptoken"),
				apptoken.WithDescription(testCtx, "test-description"),
			},
			wantErrContains: "missing created by user id",
		},
		{
			name:      "missing-expiration-time",
			scopeId:   testOrg.GetPublicId(),
			expTime:   time.Time{},
			createdBy: testUserHistoryId,
			grants: []string{
				"id=*;type=*;actions=read",
			},
			opts: []apptoken.Option{
				apptoken.WithName(testCtx, "test-apptoken"),
				apptoken.WithDescription(testCtx, "test-description"),
			},
			wantErrContains: "missing expiration time",
		},
		{
			name:      "missing-grants",
			scopeId:   testOrg.GetPublicId(),
			expTime:   testExp,
			createdBy: testUserHistoryId,
			grants:    []string{},
			opts: []apptoken.Option{
				apptoken.WithName(testCtx, "test-apptoken"),
				apptoken.WithDescription(testCtx, "test-description"),
			},
			wantErrContains: "missing grants",
		},
		{
			name:      "invalid-grant",
			scopeId:   testOrg.GetPublicId(),
			expTime:   testExp,
			createdBy: testUserHistoryId,
			grants: []string{
				"id=type=actions=read",
			},
			opts: []apptoken.Option{
				apptoken.WithName(testCtx, "test-apptoken"),
				apptoken.WithDescription(testCtx, "test-description"),
			},
			wantErrContains: "unable to parse grant string",
		},
		{
			name:      "invalid-opt",
			scopeId:   testOrg.GetPublicId(),
			expTime:   testExp,
			createdBy: testUserHistoryId,
			grants: []string{
				"id=*;type=*;actions=read",
			},
			opts: []apptoken.Option{
				apptoken.TestWithOptError(testCtx),
			},
			wantErrContains: "with opt error",
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			gotToken, gotGrants, err := testRepo.CreateAppToken(testCtx, tc.scopeId, tc.expTime, tc.createdBy, tc.grants, tc.opts...)
			if tc.wantErrContains != "" {
				require.Errorf(err, "we expected an error")
				require.Empty(gotToken)
				require.Empty(gotGrants)
				assert.Contains(err.Error(), tc.wantErrContains)
				if tc.wantErrMatch != nil {
					assert.Truef(errors.Match(tc.wantErrMatch, err), "want err code: %q got: %q", tc.wantErrMatch, err)
				}
				return
			}
			require.NoErrorf(err, "unexpected error")
			require.NotEmptyf(gotToken, "we expected an app token")

			// set fields which are set by the db
			tc.wantToken.CreateTime = gotToken.GetCreateTime()
			tc.wantToken.PublicId = gotToken.GetPublicId()

			assert.Empty(cmp.Diff(gotToken.AppToken, tc.wantToken.AppToken, protocmp.Transform()))
			assert.Len(gotGrants, len(tc.wantGrants))

			{
				// check that the appToken is in the db
				foundTk := apptoken.AllocAppToken()
				err = testRw.LookupWhere(testCtx, foundTk, "public_id = ?", []interface{}{gotToken.GetPublicId()})
				require.NoError(err)
				// this is necessary because we're not using app_token_agg so the value is not set
				foundTk.ExpirationIntervalInMaxSeconds = gotToken.ExpirationIntervalInMaxSeconds
				assert.Empty(cmp.Diff(gotToken.AppToken, foundTk.AppToken, protocmp.Transform()))
			}
			// TODO: sort grants and cmp.Diff each one

			{
				// check that the expiration interval is in the db
				if gotToken.ExpirationIntervalInMaxSeconds > 0 {
					gotExpInterval := apptoken.AllocAppTokenPeriodicExpirationInterval()
					err := testRw.LookupWhere(testCtx, gotExpInterval, "app_token_id = ?", []interface{}{gotToken.GetPublicId()})
					require.NoError(err)
					assert.Equal(gotToken.ExpirationIntervalInMaxSeconds, gotExpInterval.GetExpirationIntervalInMaxSeconds())
				}
			}

			{
				// verify that the oplog entry exists
				err = db.TestVerifyOplog(t, testRw, gotToken.GetPublicId(), db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second))
				require.NoErrorf(err, "unexpected error verifying oplog entry: %s", err)
			}
		})
	}
}

func Test_CreateAppToken_KMSGetWrapperError(t *testing.T) {
	testCtx := context.Background()
	testConn, _ := db.TestSetup(t, "postgres")
	testRw := db.New(testConn)
	testRootWrapper := db.TestWrapper(t)
	testKms := &kms.MockGetWrapperer{
		GetErr: errors.New(testCtx, errors.Encrypt, "test", "get-db-wrapper-err"),
	}
	testIamRepo := iam.TestRepo(t, testConn, testRootWrapper)
	testOrg, _ := iam.TestScopes(t, testIamRepo)
	testRepo, err := apptoken.NewRepository(testCtx, testRw, testRw, testKms, testIamRepo)
	testUser := iam.TestUser(t, testIamRepo, testOrg.GetPublicId())
	require.NoError(t, err)

	testUserHistoryId, err := testRepo.ResolveUserHistoryId(testCtx, testUser.GetPublicId())
	require.NoError(t, err)

	testExp := time.Now().Add(10 * time.Minute)

	grants := []string{
		"id=*;type=*;actions=read",
	}
	opts := []apptoken.Option{
		apptoken.WithName(testCtx, "test-apptoken"),
		apptoken.WithDescription(testCtx, "test-description"),
	}

	assert, require := assert.New(t), require.New(t)
	gotToken, gotGrants, err := testRepo.CreateAppToken(testCtx, testOrg.PublicId, testExp, testUserHistoryId, grants, opts...)
	require.Error(err)
	assert.ErrorContains(err, "get-db-wrapper-err")
	require.Empty(gotToken)
	require.Empty(gotGrants)
}
