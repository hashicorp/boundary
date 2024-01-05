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
			},
			wantToken: &apptoken.AppToken{
				AppToken: &store.AppToken{
					CreatedBy:      testUserHistoryId,
					ExpirationTime: timestamp.New(testExp.Truncate(time.Second)),
					Name:           "test-apptoken",
					Description:    "test-description",
					ScopeId:        testOrg.GetPublicId(),
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
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			gotToken, gotGrants, err := testRepo.CreateAppToken(testCtx, tc.scopeId, tc.expTime, tc.createdBy, tc.grants, tc.opts...)
			if tc.wantErrContains != "" {
				require.Errorf(err, "we expected an error")
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

			// TODO: sort grants and cmp.Diff each one
		})
	}
}
