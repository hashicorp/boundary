package tcp_test

import (
	"context"
	"testing"

	target2 "github.com/hashicorp/boundary/internal/alias/target"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/internal/target/tcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRepository_FetchAliases(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	_, staticProj := iam.TestScopes(t, iamRepo)
	ctx := context.Background()
	repo, err := target.NewRepository(ctx, rw, rw, testKms)
	require.NoError(t, err)

	tar := tcp.TestTarget(ctx, t, conn, staticProj.PublicId, "test-target")
	aname1 := "test.alias.one"
	aname2 := "test.alias.two"
	aname3 := "test.alias.three"
	aliases := make(map[string]*target2.Alias)

	t.Run("target-no-aliases", func(t *testing.T) {
		tar, err := repo.LookupTarget(context.Background(), tar.GetPublicId())
		require.NoError(t, err)

		gotAliases := tar.GetAliases()
		assert.Equal(t, len(gotAliases), 0)
	})
	t.Run("target-one-alias", func(t *testing.T) {
		al := target2.TestAlias(t, rw, aname1, target2.WithDestinationId(tar.GetPublicId()))
		aliases[aname1] = al

		tar, err := repo.LookupTarget(context.Background(), tar.GetPublicId())
		require.NoError(t, err)

		gotAliases := tar.GetAliases()
		assert.Equal(t, len(gotAliases), 1)
		assert.Equal(t, al.Value, aname1)
	})
	t.Run("target-multiple-alias", func(t *testing.T) {
		al2 := target2.TestAlias(t, rw, aname2, target2.WithDestinationId(tar.GetPublicId()))
		aliases[aname2] = al2
		al3 := target2.TestAlias(t, rw, aname3, target2.WithDestinationId(tar.GetPublicId()))
		aliases[aname3] = al3

		tar, err := repo.LookupTarget(context.Background(), tar.GetPublicId())
		require.NoError(t, err)

		gotAliases := tar.GetAliases()
		assert.Equal(t, len(gotAliases), 3)
		for _, a := range gotAliases {
			v, ok := aliases[a.Value]
			require.Equal(t, ok, true)
			require.Equal(t, a.Value, v.Value)
			require.Equal(t, a.ScopeId, v.ScopeId)
			require.Equal(t, a.Name, v.Name)
		}
	})
}
