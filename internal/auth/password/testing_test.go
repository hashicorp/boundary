// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package password

import (
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_TestAuthMethods(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	require.NotNil(org)
	assert.NotEmpty(org.GetPublicId())

	count := 4
	ams := TestAuthMethods(t, conn, org.GetPublicId(), count)
	assert.Len(ams, count)
	for _, am := range ams {
		assert.NotEmpty(am.GetPublicId())
	}
}

func Test_TestMultipleAccounts(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))

	require.NotNil(org)
	assert.NotEmpty(org.GetPublicId())

	am := TestAuthMethods(t, conn, org.GetPublicId(), 1)[0]

	count := 4
	accounts := TestMultipleAccounts(t, conn, am.GetPublicId(), count)
	assert.Len(accounts, count)
	for _, a := range accounts {
		assert.NotEmpty(a.GetPublicId())
	}
}
