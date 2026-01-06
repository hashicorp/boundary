// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package iam_test

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/auth/oidc"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test_Repository_UpdateScope_AccountInfoAuthMethodId will simply test updating
// a scope's AccountInfoAuthMethodId.  We had to make a separate test in the iam_test
// package to overcome the dreaded diamond dependency problem.
func Test_Repository_UpdateScope_AccountInfoAuthMethodId(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo := iam.TestRepo(t, conn, wrapper)
	kmsCache := kms.TestKms(t, conn, wrapper)

	t.Run("update-AccountInfoAuthMethodId", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)

		org := iam.TestOrg(t, repo)

		databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
		require.NoError(err)

		am := oidc.TestAuthMethod(t, conn, databaseWrapper, org.PublicId, oidc.ActivePublicState, "alice-rp", "fido", oidc.WithSigningAlgs(oidc.RS256), oidc.WithApiUrl(oidc.TestConvertToUrls(t, "https://www.alice.com/callback")[0]))

		org.PrimaryAuthMethodId = am.PublicId
		s, updatedRows, err := repo.UpdateScope(context.Background(), org, 1, []string{"PrimaryAuthMethodId"})
		require.NoError(err)
		assert.Equal(1, updatedRows)
		require.NotNil(s)
		assert.Equal(am.PublicId, s.PrimaryAuthMethodId)

		foundScope, err := repo.LookupScope(context.Background(), s.PublicId)
		require.NoError(err)
		assert.Equal(foundScope.PrimaryAuthMethodId, s.PrimaryAuthMethodId)

		err = db.TestVerifyOplog(t, rw, s.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second))
		assert.NoError(err)
	})
}
