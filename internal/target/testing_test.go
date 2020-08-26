package target

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/host/static"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/stretchr/testify/require"
)

func Test_TestTcpTarget(t *testing.T) {
	t.Helper()
	require := require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	_, proj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	cats := static.TestCatalogs(t, conn, proj.PublicId, 1)
	hsets := static.TestSets(t, conn, cats[0].GetPublicId(), 2)
	var sets []string
	for _, s := range hsets {
		sets = append(sets, s.PublicId)
	}
	name := testTargetName(t, proj.PublicId)
	target := TestTcpTarget(t, conn, proj.PublicId, name, WithHostSets(sets))
	require.NotNil(t)
	require.NotEmpty(target.PublicId)
	require.Equal(name, target.Name)

	rw := db.New(conn)
	foundSets, err := fetchSets(context.Background(), rw, target.PublicId)
	require.NoError(err)
	foundIds := make([]string, 0, len(foundSets))
	for _, s := range foundSets {
		foundIds = append(foundIds, s.PublicId)
	}
	require.Equal(sets, foundIds)
}
