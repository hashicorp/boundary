package tcp

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/go-uuid"
	"github.com/stretchr/testify/require"
)

// TestTarget is used to create a Target that can be used by tests in other packages.
func TestTarget(t *testing.T, conn *db.DB, scopeId, name string, opt ...target.Option) *Target {
	t.Helper()
	opt = append(opt, target.WithName(name))
	opts := target.GetOpts(opt...)
	require := require.New(t)
	rw := db.New(conn)
	tar, err := New(scopeId, opt...)
	require.NoError(err)
	id, err := db.NewPublicId(TargetPrefix)
	require.NoError(err)
	tar.PublicId = id
	err = rw.Create(context.Background(), tar)
	require.NoError(err)

	if len(opts.WithHostSources) > 0 {
		newHostSets := make([]interface{}, 0, len(opts.WithHostSources))
		for _, s := range opts.WithHostSources {
			hostSet, err := target.NewTargetHostSet(tar.PublicId, s)
			require.NoError(err)
			newHostSets = append(newHostSets, hostSet)
		}
		err := rw.CreateItems(context.Background(), newHostSets)
		require.NoError(err)
	}
	if len(opts.WithCredentialSources) > 0 {
		newCredLibs := make([]interface{}, 0, len(opts.WithCredentialSources))
		for _, cl := range opts.WithCredentialSources {
			newCl, err := target.NewCredentialLibrary(tar.PublicId, cl)
			require.NoError(err)
			newCredLibs = append(newCredLibs, newCl)
		}
		err := rw.CreateItems(context.Background(), newCredLibs)
		require.NoError(err)
	}
	return tar
}

func testTargetName(t *testing.T, scopeId string) string {
	t.Helper()
	return fmt.Sprintf("%s-%s", scopeId, testId(t))
}

func testId(t *testing.T) string {
	t.Helper()
	id, err := uuid.GenerateUUID()
	require.NoError(t, err)
	return id
}
