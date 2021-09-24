package host

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/plugin/host/store"
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
	repo, err := NewRepository(rw, rw, kmsCache)
	assert.NoError(t, err)
	assert.NotNil(t, repo)

	tests := []struct {
		name      string
		in        *Plugin
		opts      []Option
		want      *Plugin
		wantIsErr errors.Code
	}{
		{
			name:      "nil-plugin",
			wantIsErr: errors.InvalidParameter,
		},
		{
			name:      "nil-embedded-plugin",
			in:        &Plugin{},
			wantIsErr: errors.InvalidParameter,
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
		{
			name: "non-global-scope",
			in: &Plugin{
				Plugin: &store.Plugin{
					ScopeId: "o_1234567890",
				},
			},
			wantIsErr: errors.InvalidParameter,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			got, err := repo.CreatePlugin(context.Background(), tt.in, tt.opts...)
			if tt.wantIsErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantIsErr), err), "want err: %q got: %q", tt.wantIsErr, err)
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
		repo, err := NewRepository(rw, rw, kms)
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
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	plg := TestPlugin(t, conn, "test")
	badId, err := newPluginId()
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
			repo, err := NewRepository(rw, rw, kms)
			assert.NoError(err)
			assert.NotNil(repo)

			got, err := repo.LookupPlugin(context.Background(), tt.id)
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
		wantErr    errors.Code
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
			wantErr:    errors.InvalidParameter,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			kms := kms.TestKms(t, conn, wrapper)
			repo, err := NewRepository(rw, rw, kms)
			assert.NoError(err)
			assert.NotNil(repo)

			got, err := repo.LookupPluginByName(context.Background(), tt.pluginName)
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
