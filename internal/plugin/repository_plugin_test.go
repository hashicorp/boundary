// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package plugin

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/plugin/store"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRepository_CreatePlugin(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	iam.TestRepo(t, conn, wrapper)
	kmsCache := kms.TestKms(t, conn, wrapper)
	ctx := context.Background()
	repo, err := NewRepository(ctx, rw, rw, kmsCache)
	assert.NoError(t, err)
	assert.NotNil(t, repo)

	tests := []struct {
		name    string
		in      *Plugin
		opts    []Option
		want    *Plugin
		wantErr string
	}{
		{
			name:    "nil-plugin",
			wantErr: "nil Plugin",
		},
		{
			name:    "nil-embedded-plugin",
			in:      &Plugin{},
			wantErr: "nil embedded Plugin",
		},
		{
			name: "no-scope-id",
			in: &Plugin{
				Plugin: &store.Plugin{
					ScopeId: "",
				},
			},
			wantErr: "no scope id",
		},
		{
			name: "non-global-scope",
			in: &Plugin{
				Plugin: &store.Plugin{
					ScopeId: "o_1234567890",
				},
			},
			wantErr: "scope id is not 'global'",
		},
		{
			name: "public-id-not-empty",
			in: &Plugin{
				Plugin: &store.Plugin{
					PublicId: "biscuit",
					ScopeId:  "global",
				},
			},
			wantErr: "public id not empty",
		},
		{
			name: "valid-with-name",
			in: &Plugin{
				Plugin: &store.Plugin{
					Name:    "test-name-repo",
					ScopeId: scope.Global.String(),
				},
			},
			want: &Plugin{
				Plugin: &store.Plugin{
					Name:    "test-name-repo",
					ScopeId: scope.Global.String(),
				},
			},
		},
		{
			name: "valid-with-description",
			in: &Plugin{
				Plugin: &store.Plugin{
					Description: "test-description-repo",
					ScopeId:     scope.Global.String(),
				},
			},
			want: &Plugin{
				Plugin: &store.Plugin{
					Description: "test-description-repo",
					ScopeId:     scope.Global.String(),
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			got, err := repo.CreatePlugin(context.Background(), tt.in, tt.opts...)
			if tt.wantErr != "" {
				assert.ErrorContains(err, tt.wantErr)
				assert.Nil(got)
				return
			}
			require.NoError(t, err)
			assert.NoError(err)
			assert.Empty(tt.in.PublicId)
			assert.NotNil(got)
			assertPublicId(t, PluginPrefix, got.PublicId)
			assert.NotSame(tt.in, got)
			assert.Equal(tt.want.Name, got.Name)
			assert.Equal(tt.want.Description, got.Description)
			assert.Equal(got.CreateTime, got.UpdateTime)
		})
	}

	t.Run("invalid-duplicate-names", func(t *testing.T) {
		assert := assert.New(t)
		kms := kms.TestKms(t, conn, wrapper)
		ctx := context.Background()
		repo, err := NewRepository(ctx, rw, rw, kms)
		assert.NoError(err)
		assert.NotNil(repo)
		in := &Plugin{
			Plugin: &store.Plugin{
				ScopeId: scope.Global.String(),
				Name:    "invalid-duplicate-names",
			},
		}

		got, err := repo.CreatePlugin(context.Background(), in)
		assert.NoError(err)
		assert.NotNil(got)
		assertPublicId(t, PluginPrefix, got.PublicId)
		assert.NotSame(in, got)
		assert.Equal(in.Name, got.Name)
		assert.Equal(in.Description, got.Description)
		assert.Equal(got.CreateTime, got.UpdateTime)

		got2, err := repo.CreatePlugin(context.Background(), in)
		assert.Truef(errors.Match(errors.T(errors.NotUnique), err), "want err code: %v got err: %v", errors.NotUnique, err)
		assert.Nil(got2)
	})
}

func assertPublicId(t *testing.T, prefix, actual string) {
	t.Helper()
	assert.NotEmpty(t, actual)
	parts := strings.Split(actual, "_")
	assert.Equalf(t, 2, len(parts), "want one '_' in PublicId, got multiple in %q", actual)
	assert.Equalf(t, prefix, parts[0], "PublicId want prefix: %q, got: %q in %q", prefix, parts[0], actual)
}

func TestRepository_LookupPlugin(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	plg := TestPlugin(t, conn, "test")
	badId, err := newPluginId(ctx)
	assert.NoError(t, err)
	assert.NotNil(t, badId)

	tests := []struct {
		name    string
		id      string
		want    *Plugin
		wantErr errors.Code
	}{
		{
			name: "found",
			id:   plg.GetPublicId(),
			want: plg,
		},
		{
			name: "not-found",
			id:   badId,
			want: nil,
		},
		{
			name:    "bad-public-id",
			id:      "",
			want:    nil,
			wantErr: errors.InvalidParameter,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			kms := kms.TestKms(t, conn, wrapper)
			repo, err := NewRepository(ctx, rw, rw, kms)
			assert.NoError(err)
			assert.NotNil(repo)

			got, err := repo.LookupPlugin(ctx, tt.id)
			if tt.wantErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantErr), err), "want err: %q got: %q", tt.wantErr, err)
				return
			}
			assert.NoError(err)

			switch {
			case tt.want == nil:
				assert.Nil(got)
			case tt.want != nil:
				assert.NotNil(got)
				assert.Equal(got, tt.want)
			}
		})
	}
}

func TestRepository_LookupPluginByName(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	plg := TestPlugin(t, conn, "name123")

	tests := []struct {
		name       string
		pluginName string
		want       *Plugin
		wantErr    string
	}{
		{
			name:       "found",
			pluginName: plg.GetName(),
			want:       plg,
		},
		{
			name:       "not-found",
			pluginName: "randomname",
			want:       nil,
		},
		{
			name:       "emptyname",
			pluginName: "",
			want:       nil,
			wantErr:    "no plugin name",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			kms := kms.TestKms(t, conn, wrapper)
			ctx := context.Background()
			repo, err := NewRepository(ctx, rw, rw, kms)
			assert.NoError(err)
			assert.NotNil(repo)

			got, err := repo.LookupPluginByName(context.Background(), tt.pluginName)
			if tt.wantErr != "" {
				assert.ErrorContains(err, tt.wantErr)
				assert.Nil(got)
				return
			}
			assert.NoError(err)

			switch {
			case tt.want == nil:
				assert.Nil(got)
			case tt.want != nil:
				assert.NotNil(got)
				assert.Equal(got, tt.want)
			}
		})
	}
}

func TestRepository_AddSupportFlag(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)

	tests := []struct {
		name       string
		pluginName string
		table      string
		flag       PluginType
		flagExists bool
		forceErr   bool
		err        string
	}{
		{
			name:       "flag doesn't exist and is added",
			pluginName: "test1",
			table:      "plugin_host_supported",
			flag:       PluginTypeHost,
			flagExists: false,
			forceErr:   false,
			err:        "",
		},
		{
			name:       "flag exists and is unchanged",
			pluginName: "test2",
			table:      "plugin_host_supported",
			flag:       PluginTypeHost,
			flagExists: true,
			forceErr:   false,
			err:        "",
		},
		{
			name:       "err thrown and is handled",
			pluginName: "test3",
			table:      "plugin_host_supported",
			flag:       PluginTypeHost,
			flagExists: false,
			forceErr:   true,
			err:        "wt_plugin_id_check constraint failed",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			require := require.New(t)
			ctx := context.Background()

			// require.Contains(pluginTypeDbMap, tt.flag)
			plg := TestPlugin(t, conn, tt.pluginName, WithHostFlag(tt.flagExists))

			// check to make sure the start state is as expected
			rows, err := rw.Query(ctx, fmt.Sprintf("select public_id from %s where public_id = ?;", tt.table), []any{plg.PublicId})
			require.NoError(err)

			rowCount := 0
			var plgid string

			for rows.Next() {
				rowCount++
				require.NoError(rows.Scan(&plgid))
			}
			require.NoError(rows.Err())

			if tt.flagExists {
				assert.Equal(1, rowCount)
				assert.Equal(plg.PublicId, plgid)
			} else {
				assert.Equal(0, rowCount)
				assert.Equal("", plgid)
			}

			// create the plugin repo
			kms := kms.TestKms(t, conn, wrapper)
			repo, err := NewRepository(ctx, rw, rw, kms)
			assert.NoError(err)
			assert.NotNil(repo)

			if tt.forceErr {
				plg.PublicId = "biscuit"
			}

			// do the thing
			err = repo.AddSupportFlag(ctx, plg, tt.flag)

			if tt.err != "" {
				require.ErrorContains(err, tt.err)
				return
			}
			require.NoError(err)

			// check to make sure the end state is as expected
			rows, err = rw.Query(ctx, fmt.Sprintf("select public_id from %s where public_id = ?;", tt.table), []any{plg.PublicId})
			require.NoError(err)
			rowCount = 0
			for rows.Next() {
				rowCount++
			}
			require.NoError(rows.Err())
			assert.Equal(1, rowCount)
		})
	}

	// this needs it's own test becaues of the setup required for above tests
	t.Run("plugin type unknown", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)
		ctx := context.Background()
		plg := TestPlugin(t, conn, "test12345")

		// create the plugin repo
		kms := kms.TestKms(t, conn, wrapper)
		repo, err := NewRepository(ctx, rw, rw, kms)
		assert.NoError(err)
		assert.NotNil(repo)

		// do the thing
		err = repo.AddSupportFlag(ctx, plg, PluginTypeUnknown)

		require.ErrorContains(err, "plugin type does not exist: parameter violation")
	})
}
