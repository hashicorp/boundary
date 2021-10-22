package tcp_test

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/credential/vault"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/host/static"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/internal/target/tcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_TestTcpTarget(t *testing.T) {
	require := require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	_, proj := iam.TestScopes(t, iamRepo)
	repo, err := target.NewRepository(rw, rw, testKms)
	require.NoError(err)

	cats := static.TestCatalogs(t, conn, proj.PublicId, 1)
	hsets := static.TestSets(t, conn, cats[0].GetPublicId(), 2)
	var sets []string
	for _, s := range hsets {
		sets = append(sets, s.PublicId)
	}
	name := tcp.TestTargetName(t, proj.PublicId)
	tar := tcp.TestTarget(t, conn, proj.PublicId, name, target.WithHostSources(sets))
	require.NotNil(t)
	require.NotEmpty(tar.PublicId)
	require.Equal(name, tar.Name)

	_, foundSources, _, err := repo.LookupTarget(context.Background(), tar.PublicId)
	require.NoError(err)
	foundIds := make([]string, 0, len(foundSources))
	for _, s := range foundSources {
		foundIds = append(foundIds, s.Id())
	}
	require.Equal(sets, foundIds)
}

func Test_TestCredentialLibrary(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	_, proj := iam.TestScopes(t, iamRepo)
	repo, err := target.NewRepository(rw, rw, testKms)
	require.NoError(err)

	tar := tcp.TestTarget(t, conn, proj.PublicId, t.Name())
	store := vault.TestCredentialStores(t, conn, wrapper, proj.GetPublicId(), 1)[0]
	vlibs := vault.TestCredentialLibraries(t, conn, wrapper, store.GetPublicId(), 2)
	var libIds []string
	var libs []*target.CredentialLibrary
	for _, v := range vlibs {
		libIds = append(libIds, v.GetPublicId())
		lib := target.TestCredentialLibrary(t, conn, tar.GetPublicId(), v.GetPublicId())
		require.NotNil(lib)
		libs = append(libs, lib)
	}

	assert.Len(libs, 2)

	_, _, foundSources, err := repo.LookupTarget(context.Background(), tar.PublicId)
	require.NoError(err)
	foundIds := make([]string, 0, len(foundSources))
	for _, s := range foundSources {
		foundIds = append(foundIds, s.Id())
	}
	require.Equal(libIds, foundIds)
}
