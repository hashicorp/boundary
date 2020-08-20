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
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	cats := static.TestCatalogs(t, conn, org.PublicId, 1)
	hsets := static.TestSets(t, conn, cats[0].GetPublicId(), 2)
	var sets []string
	for _, s := range hsets {
		sets = append(sets, s.PublicId)
	}
	name := testTargetName(t, org.PublicId)
	target := TestTcpTarget(t, conn, org.PublicId, name, WithHostSets(sets))
	require.NotNil(t)
	require.NotEmpty(target.PublicId)
	require.Equal(name, target.Name)

	rw := db.New(conn)
	foundSets, err := fetchHostSets(context.Background(), rw, target.PublicId)
	require.NoError(err)
	require.Equal(sets, foundSets)
}
