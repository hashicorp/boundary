package host

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/plugin/host/store"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/stretchr/testify/require"
)

func TestNewPluginManagerNoRepo(t *testing.T) {
	_, err := NewPluginManager(context.Background(), nil)
	wantErr := errors.New(context.Background(), errors.InvalidParameter, "host.NewPluginManager", "missing underlying repo")
	require.Truef(t, errors.Match(errors.T(wantErr), err), "want err: %q got: %q", wantErr, err)
}

func TestLoadPluginNoId(t *testing.T) {
	require := require.New(t)

	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	iam.TestRepo(t, conn, wrapper)
	kmsCache := kms.TestKms(t, conn, wrapper)
	repo, err := NewRepository(rw, rw, kmsCache)
	require.NoError(err)
	require.NotNil(repo)

	manager, err := NewPluginManager(context.Background(), repo)
	require.NoError(err)

	_, err = manager.LoadPlugin(context.Background(), "")
	wantErr := errors.New(context.Background(), errors.InvalidParameter, "host.(PluginManager).LoadPlugin", "no plugin id")
	require.Truef(errors.Match(errors.T(wantErr), err), "want err: %q got: %q", wantErr, err)
}

func TestLoadPluginIdNotFound(t *testing.T) {
	require := require.New(t)

	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	iam.TestRepo(t, conn, wrapper)
	kmsCache := kms.TestKms(t, conn, wrapper)
	repo, err := NewRepository(rw, rw, kmsCache)
	require.NoError(err)
	require.NotNil(repo)

	manager, err := NewPluginManager(context.Background(), repo)
	require.NoError(err)

	_, err = manager.LoadPlugin(context.Background(), "missing")
	wantErr := errors.New(context.Background(), errors.RecordNotFound, "host.(PluginManager).LoadPlugin", "could not find plugin for id \"missing\"")
	require.Truef(errors.Match(errors.T(wantErr), err), "want err: %q got: %q", wantErr, err)
}

func TestLoadPluginEmbeddedNotRegistered(t *testing.T) {
	require := require.New(t)

	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	iam.TestRepo(t, conn, wrapper)
	kmsCache := kms.TestKms(t, conn, wrapper)
	repo, err := NewRepository(rw, rw, kmsCache)
	require.NoError(err)
	require.NotNil(repo)

	plugin, err := repo.CreatePlugin(context.Background(), &Plugin{
		Plugin: &store.Plugin{
			ScopeId:    scope.Global.String(),
			IdPrefix:   "missing",
			PluginName: "missing",
		},
	})
	require.NoError(err)

	manager, err := NewPluginManager(context.Background(), repo)
	require.NoError(err)

	_, err = manager.LoadPlugin(context.Background(), plugin.PublicId)
	wantErr := errors.New(context.Background(), errors.InvalidParameter, "host.(PluginManager).LoadPlugin", "plugin with name \"missing\" is not an embedded plugin")
	require.Truef(errors.Match(errors.T(wantErr), err), "want err: %q got: %q", wantErr, err)
}

func TestLoadPluginEmbeddedValid(t *testing.T) {
	require := require.New(t)

	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	iam.TestRepo(t, conn, wrapper)
	kmsCache := kms.TestKms(t, conn, wrapper)
	repo, err := NewRepository(rw, rw, kmsCache)
	require.NoError(err)
	require.NotNil(repo)

	plugin, err := repo.CreatePlugin(context.Background(), &Plugin{
		Plugin: &store.Plugin{
			ScopeId:    scope.Global.String(),
			IdPrefix:   "testing",
			PluginName: "testing",
		},
	})
	require.NoError(err)

	manager, err := NewPluginManager(context.Background(), repo)
	require.NoError(err)

	client, err := manager.LoadPlugin(context.Background(), plugin.PublicId)
	require.NoError(err)
	require.NotNil(client)
}
