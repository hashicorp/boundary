// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package apptoken

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_TestAppToken(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	testCtx := context.Background()
	testConn, _ := db.TestSetup(t, "postgres")
	testRw := db.New(testConn)
	testRootWrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, testConn, testRootWrapper)
	testIamRepo := iam.TestRepo(t, testConn, testRootWrapper)
	testOrg, _ := iam.TestScopes(t, testIamRepo)
	testRepo, err := NewRepository(testCtx, testRw, testRw, testKms, testIamRepo)
	testUser := iam.TestUser(t, testIamRepo, testOrg.GetPublicId())
	require.NoError(err)

	testUserHistoryId, err := testRepo.ResolveUserHistoryId(testCtx, testUser.GetPublicId())
	require.NoError(err)

	at, atg := TestAppToken(t, testConn, testOrg.PublicId, testUserHistoryId, "id=*;type=*;actions=*")

	assert.NotEmpty(at.GetPublicId())
	assert.Len(atg, 1)
}
