// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package target_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/alias/target"
	"github.com/hashicorp/boundary/internal/alias/target/store"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/target/tcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestNewAlias(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		a, err := target.NewAlias(context.Background(), "global", "valid.alias")
		require.NoError(t, err)
		assert.NotNil(t, a)
		assert.Equal(t, a.ScopeId, "global")
		assert.Equal(t, a.Value, "valid.alias")
	})

	t.Run("with destination", func(t *testing.T) {
		a, err := target.NewAlias(context.Background(), "global", "with.destination", target.WithDestinationId("ttcp_1234567890"))
		require.NoError(t, err)
		assert.NotNil(t, a)
		assert.Equal(t, a.ScopeId, "global")
		assert.Equal(t, a.Value, "with.destination")
		assert.Equal(t, a.DestinationId, "ttcp_1234567890")
	})
}

func TestCreate(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	ctx := context.Background()
	wrapper := db.TestWrapper(t)

	iamRepo := iam.TestRepo(t, conn, wrapper)
	_, proj := iam.TestScopes(t, iamRepo)
	tar := tcp.TestTarget(ctx, t, conn, proj.GetPublicId(), "test")

	cases := []struct {
		name        string
		scope       string
		value       string
		opts        []target.Option
		validate    func(*testing.T, *target.Alias)
		errContains string
	}{
		{
			name:  "valid",
			scope: "global",
			value: "valid.alias",
			opts:  []target.Option{target.WithDestinationId(tar.GetPublicId())},
			validate: func(t *testing.T, a *target.Alias) {
				t.Helper()
				assert.Equal(t, a.DestinationId, tar.GetPublicId())
			},
		},
		{
			name:  "valid with host",
			scope: "global",
			value: "host.valid.alias",
			opts:  []target.Option{target.WithDestinationId(tar.GetPublicId()), target.WithHostId("hst_1234567890")},
			validate: func(t *testing.T, a *target.Alias) {
				t.Helper()
				assert.Equal(t, a.DestinationId, tar.GetPublicId())
				assert.Equal(t, a.HostId, "hst_1234567890")
			},
		},
		{
			name:  "valid no destination",
			scope: "global",
			value: "nodestination.alias",
			validate: func(t *testing.T, a *target.Alias) {
				t.Helper()
				assert.Empty(t, a.DestinationId)
			},
		},
		{
			name:  "valid with name",
			scope: "global",
			value: "valid-with-name.alias",
			opts:  []target.Option{target.WithName("valid-with-name")},
			validate: func(t *testing.T, a *target.Alias) {
				t.Helper()
				assert.Equal(t, "valid-with-name", a.Name)
			},
		},
		{
			name:  "valid with description",
			scope: "global",
			value: "valid-with-description.alias",
			opts:  []target.Option{target.WithName("valid-with-description"), target.WithDescription("a description")},
			validate: func(t *testing.T, a *target.Alias) {
				t.Helper()
				assert.Equal(t, "valid-with-description", a.Name)
				assert.Equal(t, "a description", a.Description)
			},
		},
		{
			name:        "host with no destination",
			scope:       "global",
			value:       "host.with.no.destination",
			opts:        []target.Option{target.WithHostId("hst_1234567890")},
			errContains: `destination_id_set_when_host_id_is_set constraint failed`,
		},
		{
			name:        "unsupported project scope",
			scope:       proj.GetPublicId(),
			value:       "unsupported.project.scope",
			errContains: `alias_must_be_in_global_scope constraint failed`,
		},
		{
			name:        "unsupported org scope",
			scope:       proj.GetParentId(),
			value:       "unsupported.org.scope",
			errContains: `alias_must_be_in_global_scope constraint failed`,
		},
		{
			name:        "invalid scope",
			scope:       "invalid",
			value:       "invalid.scope",
			errContains: `wt_scope_id_check constraint failed`,
		},
		{
			name:        "invalid dest",
			scope:       "global",
			value:       "invalid.dest",
			opts:        []target.Option{target.WithDestinationId("ttcp_unknown")},
			errContains: `foreign key constraint "target_fkey"`,
		},
		{
			name:        "invalid alias",
			scope:       "global",
			value:       "-not-valid-dns-name-",
			errContains: "wt_target_alias_value_shape constraint failed",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, err := target.NewAlias(ctx, c.scope, c.value, c.opts...)
			require.NoError(t, err)
			assert.NotNil(t, a)
			a.PublicId, err = db.NewPublicId(ctx, globals.TargetAliasPrefix)
			require.NoError(t, err)

			start := time.Now().UTC().Round(time.Second)

			err = rw.Create(ctx, a)
			if c.errContains != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), c.errContains)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, a)
				assert.Equal(t, a.Version, uint32(1))
				assert.Equal(t, a.ScopeId, c.scope)
				assert.Equal(t, a.Value, c.value)
				assert.GreaterOrEqual(t, a.CreateTime.AsTime().Round(time.Second), start)
				assert.GreaterOrEqual(t, a.UpdateTime.AsTime().Round(time.Second), start)
				if c.validate != nil {
					c.validate(t, a)
				}
			}
		})
	}

	t.Run("case insensitive duplicate alias", func(t *testing.T) {
		a := target.TestAlias(t, rw, "duplicate.alias")
		t.Cleanup(func() {
			_, err := rw.Delete(ctx, a)
			require.NoError(t, err)
		})

		var err error
		a.PublicId, err = db.NewPublicId(ctx, globals.TargetAliasPrefix)
		require.NoError(t, err)
		a.Value = "DUPLICATE.ALIAS"
		err = rw.Create(ctx, a)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), `duplicate key value violates unique constraint "alias_value_uq"`)
	})
}

func TestUpdate(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	ctx := context.Background()
	wrapper := db.TestWrapper(t)

	iamRepo := iam.TestRepo(t, conn, wrapper)
	_, proj := iam.TestScopes(t, iamRepo)
	tar1 := tcp.TestTarget(ctx, t, conn, proj.GetPublicId(), "test")
	tar2 := tcp.TestTarget(ctx, t, conn, proj.GetPublicId(), "test2")

	cases := []struct {
		name            string
		startingOptions []target.Option
		in              *target.Alias
		fieldMask       []string
		nullMask        []string
		want            *target.Alias
		errContains     string
	}{
		{
			name: "update alias value",
			in: &target.Alias{
				Alias: &store.Alias{Value: "updated.alias"},
			},
			fieldMask: []string{"Value"},
			want: &target.Alias{
				Alias: &store.Alias{
					ScopeId: "global",
					Value:   "updated.alias",
				},
			},
		},
		{
			name: "remove alias value",
			in: &target.Alias{
				Alias: &store.Alias{},
			},
			fieldMask:   []string{"Value"},
			errContains: `wt_alias_too_short constraint failed:`,
		},
		{
			name:            "update destination id",
			startingOptions: []target.Option{target.WithDestinationId(tar1.GetPublicId())},
			in: &target.Alias{
				Alias: &store.Alias{DestinationId: tar2.GetPublicId()},
			},
			fieldMask: []string{"DestinationId"},
			want: &target.Alias{
				Alias: &store.Alias{
					ScopeId:       "global",
					Value:         "test.alias",
					DestinationId: tar2.GetPublicId(),
				},
			},
		},
		{
			name: "update destination id with host id",
			startingOptions: []target.Option{
				target.WithDestinationId(tar1.GetPublicId()),
				target.WithHostId("hst_1234567890"),
			},
			in: &target.Alias{
				Alias: &store.Alias{
					DestinationId: tar2.GetPublicId(),
				},
			},
			fieldMask: []string{"DestinationId"},
			want: &target.Alias{
				Alias: &store.Alias{
					ScopeId:       "global",
					Value:         "test.alias",
					DestinationId: tar2.GetPublicId(),
					HostId:        "hst_1234567890",
				},
			},
		},
		{
			name:            "remove destination id",
			startingOptions: []target.Option{target.WithDestinationId(tar1.GetPublicId())},
			in: &target.Alias{
				Alias: &store.Alias{},
			},
			nullMask: []string{"DestinationId"},
			want: &target.Alias{
				Alias: &store.Alias{
					ScopeId: "global",
					Value:   "test.alias",
				},
			},
		},
		{
			name: "remove destination id with host id",
			startingOptions: []target.Option{
				target.WithDestinationId(tar1.GetPublicId()),
				target.WithHostId("hst_1234567890"),
			},
			in: &target.Alias{
				Alias: &store.Alias{},
			},
			nullMask: []string{"DestinationId"},
			want: &target.Alias{
				Alias: &store.Alias{
					ScopeId: "global",
					Value:   "test.alias",
				},
			},
		},
		{
			name: "update host id",
			startingOptions: []target.Option{
				target.WithDestinationId(tar1.GetPublicId()),
				target.WithHostId("hst_1234567890"),
			},
			in: &target.Alias{
				Alias: &store.Alias{
					HostId: "hst_0987654321",
				},
			},
			fieldMask: []string{"HostId"},
			want: &target.Alias{
				Alias: &store.Alias{
					ScopeId:       "global",
					Value:         "test.alias",
					DestinationId: tar1.GetPublicId(),
					HostId:        "hst_0987654321",
				},
			},
		},
		{
			name: "remove host id",
			startingOptions: []target.Option{
				target.WithDestinationId(tar1.GetPublicId()),
				target.WithHostId("hst_1234567890"),
			},
			in: &target.Alias{
				Alias: &store.Alias{},
			},
			nullMask: []string{"HostId"},
			want: &target.Alias{
				Alias: &store.Alias{
					ScopeId:       "global",
					Value:         "test.alias",
					DestinationId: tar1.GetPublicId(),
				},
			},
		},
		{
			name: "update name",
			startingOptions: []target.Option{
				target.WithName("updateName"),
			},
			in: &target.Alias{
				Alias: &store.Alias{
					Name: "updateName-updated",
				},
			},
			fieldMask: []string{"Name"},
			want: &target.Alias{
				Alias: &store.Alias{
					ScopeId: "global",
					Name:    "updateName-updated",
					Value:   "test.alias",
				},
			},
		},
		{
			name: "remove name",
			startingOptions: []target.Option{
				target.WithName("updateName"),
			},
			in: &target.Alias{
				Alias: &store.Alias{},
			},
			nullMask: []string{"Name"},
			want: &target.Alias{
				Alias: &store.Alias{
					ScopeId: "global",
					Value:   "test.alias",
				},
			},
		},
		{
			name: "update description",
			startingOptions: []target.Option{
				target.WithDescription("description"),
			},
			in: &target.Alias{
				Alias: &store.Alias{
					Description: "description-updated",
				},
			},
			fieldMask: []string{"Description"},
			want: &target.Alias{
				Alias: &store.Alias{
					ScopeId:     "global",
					Description: "description-updated",
					Value:       "test.alias",
				},
			},
		},
		{
			name: "remove description",
			startingOptions: []target.Option{
				target.WithDescription("description"),
			},
			in: &target.Alias{
				Alias: &store.Alias{},
			},
			nullMask: []string{"Description"},
			want: &target.Alias{
				Alias: &store.Alias{
					ScopeId: "global",
					Value:   "test.alias",
				},
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := target.TestAlias(t, rw, "test.alias", c.startingOptions...)
			t.Cleanup(func() {
				_, err := rw.Delete(ctx, a)
				require.NoError(t, err)
			})
			cp := proto.Clone(c.in.Alias)
			in := &target.Alias{
				Alias: cp.(*store.Alias),
			}
			in.PublicId = a.PublicId
			in.Version = a.Version

			_, err := rw.Update(ctx, in, c.fieldMask, c.nullMask)
			if c.errContains != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), c.errContains)
			} else {
				require.NoError(t, err)
				assert.Greater(t, in.UpdateTime.AsTime(), in.CreateTime.AsTime())

				c.want.Version = 2
				c.want.PublicId = a.PublicId
				in.UpdateTime = nil
				in.CreateTime = nil
				assert.Empty(t, cmp.Diff(c.want, in, protocmp.Transform()))
			}
		})
	}
}

func TestDelete(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	ctx := context.Background()

	t.Run("delete existing", func(t *testing.T) {
		a := target.TestAlias(t, rw, "alias.to.delete")
		n, err := rw.Delete(ctx, a)
		assert.NoError(t, err)
		assert.Equal(t, 1, n)
	})

	t.Run("delete existing with destination", func(t *testing.T) {
		_, p := iam.TestScopes(t, iam.TestRepo(t, conn, db.TestWrapper(t)))
		tar := tcp.TestTarget(ctx, t, conn, p.GetPublicId(), "test")
		a := target.TestAlias(t, rw, "alias.with.destination", target.WithDestinationId(tar.GetPublicId()))
		n, err := rw.Delete(ctx, a)
		assert.NoError(t, err)
		assert.Equal(t, 1, n)
	})

	t.Run("delete non-existent", func(t *testing.T) {
		a := &target.Alias{
			Alias: &store.Alias{},
		}
		a.PublicId = "alias_does_not_exist"
		n, err := rw.Delete(ctx, a)
		assert.NoError(t, err)
		assert.Equal(t, 0, n)
	})
}
