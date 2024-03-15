// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package apptoken

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/go-dbw"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRepository_DeleteAppToken(t *testing.T) {
	testCtx := context.Background()
	testConn, _ := db.TestSetup(t, "postgres")
	testRw := db.New(testConn)
	testWrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, testConn, testWrapper)
	testIamRepo := iam.TestRepo(t, testConn, testWrapper)
	testOrg, _ := iam.TestScopes(t, testIamRepo)
	testRepo, err := NewRepository(testCtx, testRw, testRw, testKms, testIamRepo)
	require.NoError(t, err)
	testUser := iam.TestUser(t, testIamRepo, testOrg.GetPublicId())
	testUserHistoryId, err := testRepo.ResolveUserHistoryId(testCtx, testUser.GetPublicId())
	require.NoError(t, err)
	grants := "ids=*;type=*;actions=*"

	tests := []struct {
		name            string
		id              string
		wantRowsDeleted int
		wantErrMatch    *errors.Template
		wantErrContains string
	}{
		{
			name: "valid",
			id: func() string {
				at := TestAppToken(t, testConn, testOrg.PublicId, testUserHistoryId, grants)
				return at.PublicId
			}(),
			wantRowsDeleted: 1,
		},
		{
			name:            "no-public-id",
			id:              "",
			wantErrMatch:    errors.T(errors.InvalidPublicId),
			wantErrContains: "missing public id",
		},
		{
			name:            "not-found",
			id:              "apt_fakeid",
			wantRowsDeleted: 0,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			count, err := testRepo.DeleteAppToken(testCtx, tc.id)
			if tc.wantErrContains != "" {
				require.Error(err)
				assert.Contains(err.Error(), tc.wantErrContains)
				if tc.wantErrMatch != nil {
					assert.True(errors.Match(tc.wantErrMatch, err), "error does not match")
				}
				assert.Zero(count)
				return
			}
			require.NoError(err)
			assert.Equal(tc.wantRowsDeleted, count)

			found := AllocAppToken()
			found.PublicId = tc.id
			err = testRw.LookupById(testCtx, found)
			assert.Error(err)
			assert.ErrorIs(err, dbw.ErrRecordNotFound)
		})
	}
}
