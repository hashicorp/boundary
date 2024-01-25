// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package target

import (
	"context"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/internal/alias/target/store"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/target/tcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestNewAlias(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		a, err := NewAlias(context.Background(), "global", "valid.alias")
		require.NoError(t, err)
		assert.NotNil(t, a)
		assert.Equal(t, a.ScopeId, "global")
		assert.Equal(t, a.Value, "valid.alias")
	})

	t.Run("missing value", func(t *testing.T) {
		_, err := NewAlias(context.Background(), "global", "")
		assert.ErrorContains(t, err, "alias value must be specified")
	})

	t.Run("missing scope", func(t *testing.T) {
		_, err := NewAlias(context.Background(), "", "missing.scope")
		assert.ErrorContains(t, err, "scope id must be specified")
	})

	t.Run("with destination", func(t *testing.T) {
		a, err := NewAlias(context.Background(), "global", "with.destination", WithDestinationId("ttcp_1234567890"))
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
		opts        []Option
		validate    func(*testing.T, *Alias)
		errContains string
	}{
		{
			name:  "valid",
			scope: "global",
			value: "valid.alias",
			opts:  []Option{WithDestinationId(tar.GetPublicId())},
			validate: func(t *testing.T, a *Alias) {
				t.Helper()
				assert.Equal(t, a.DestinationId, tar.GetPublicId())
			},
		},
		{
			name:  "valid with host",
			scope: "global",
			value: "host.valid.alias",
			opts:  []Option{WithDestinationId(tar.GetPublicId()), WithHostId("hst_1234567890")},
			validate: func(t *testing.T, a *Alias) {
				t.Helper()
				assert.Equal(t, a.DestinationId, tar.GetPublicId())
				assert.Equal(t, a.HostId, "hst_1234567890")
			},
		},
		{
			name:  "valid no destination",
			scope: "global",
			value: "nodestination.alias",
			validate: func(t *testing.T, a *Alias) {
				t.Helper()
				assert.Empty(t, a.DestinationId)
			},
		},
		{
			name:  "valid with name",
			scope: "global",
			value: "valid-with-name.alias",
			opts:  []Option{WithName("valid-with-name")},
			validate: func(t *testing.T, a *Alias) {
				t.Helper()
				assert.Equal(t, "valid-with-name", a.Name)
			},
		},
		{
			name:  "valid with description",
			scope: "global",
			value: "valid-with-description.alias",
			opts:  []Option{WithName("valid-with-description"), WithDescription("a description")},
			validate: func(t *testing.T, a *Alias) {
				t.Helper()
				assert.Equal(t, "valid-with-description", a.Name)
				assert.Equal(t, "a description", a.Description)
			},
		},
		{
			name:        "host with no destination",
			scope:       "global",
			value:       "host.with.no.destination",
			opts:        []Option{WithHostId("hst_1234567890")},
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
			opts:        []Option{WithDestinationId("ttcp_unknown")},
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
			a, err := NewAlias(ctx, c.scope, c.value, c.opts...)
			require.NoError(t, err)
			assert.NotNil(t, a)
			a.PublicId, err = newAliasId(ctx)
			require.NoError(t, err)

			start := time.Now().UTC()

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
				assert.GreaterOrEqual(t, a.CreateTime.AsTime(), start)
				assert.GreaterOrEqual(t, a.UpdateTime.AsTime(), start)
				if c.validate != nil {
					c.validate(t, a)
				}
			}
		})
	}

	t.Run("case insensitive duplicate alias", func(t *testing.T) {
		a := TestAlias(t, rw, "duplicate.alias")
		t.Cleanup(func() {
			_, err := rw.Delete(ctx, a)
			require.NoError(t, err)
		})

		var err error
		a.PublicId, err = newAliasId(ctx)
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
		startingOptions []Option
		in              *Alias
		fieldMask       []string
		nullMask        []string
		want            *Alias
		errContains     string
	}{
		{
			name: "update alias value",
			in: &Alias{
				Alias: &store.Alias{Value: "updated.alias"},
			},
			fieldMask: []string{"Value"},
			want: &Alias{
				Alias: &store.Alias{
					ScopeId: "global",
					Value:   "updated.alias",
				},
			},
		},
		{
			name: "remove alias value",
			in: &Alias{
				Alias: &store.Alias{},
			},
			fieldMask:   []string{"Value"},
			errContains: `wt_alias_too_short constraint failed:`,
		},
		{
			name:            "update destination id",
			startingOptions: []Option{WithDestinationId(tar1.GetPublicId())},
			in: &Alias{
				Alias: &store.Alias{DestinationId: tar2.GetPublicId()},
			},
			fieldMask: []string{"DestinationId"},
			want: &Alias{
				Alias: &store.Alias{
					ScopeId:       "global",
					Value:         "test.alias",
					DestinationId: tar2.GetPublicId(),
				},
			},
		},
		{
			name: "update destination id with host id",
			startingOptions: []Option{
				WithDestinationId(tar1.GetPublicId()),
				WithHostId("hst_1234567890"),
			},
			in: &Alias{
				Alias: &store.Alias{
					DestinationId: tar2.GetPublicId(),
				},
			},
			fieldMask: []string{"DestinationId"},
			want: &Alias{
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
			startingOptions: []Option{WithDestinationId(tar1.GetPublicId())},
			in: &Alias{
				Alias: &store.Alias{},
			},
			nullMask: []string{"DestinationId"},
			want: &Alias{
				Alias: &store.Alias{
					ScopeId: "global",
					Value:   "test.alias",
				},
			},
		},
		{
			name: "remove destination id with host id",
			startingOptions: []Option{
				WithDestinationId(tar1.GetPublicId()),
				WithHostId("hst_1234567890"),
			},
			in: &Alias{
				Alias: &store.Alias{},
			},
			nullMask: []string{"DestinationId"},
			want: &Alias{
				Alias: &store.Alias{
					ScopeId: "global",
					Value:   "test.alias",
				},
			},
		},
		{
			name: "update host id",
			startingOptions: []Option{
				WithDestinationId(tar1.GetPublicId()),
				WithHostId("hst_1234567890"),
			},
			in: &Alias{
				Alias: &store.Alias{
					HostId: "hst_0987654321",
				},
			},
			fieldMask: []string{"HostId"},
			want: &Alias{
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
			startingOptions: []Option{
				WithDestinationId(tar1.GetPublicId()),
				WithHostId("hst_1234567890"),
			},
			in: &Alias{
				Alias: &store.Alias{},
			},
			nullMask: []string{"HostId"},
			want: &Alias{
				Alias: &store.Alias{
					ScopeId:       "global",
					Value:         "test.alias",
					DestinationId: tar1.GetPublicId(),
				},
			},
		},
		{
			name: "update name",
			startingOptions: []Option{
				WithName("updateName"),
			},
			in: &Alias{
				Alias: &store.Alias{
					Name: "updateName-updated",
				},
			},
			fieldMask: []string{"Name"},
			want: &Alias{
				Alias: &store.Alias{
					ScopeId: "global",
					Name:    "updateName-updated",
					Value:   "test.alias",
				},
			},
		},
		{
			name: "remove name",
			startingOptions: []Option{
				WithName("updateName"),
			},
			in: &Alias{
				Alias: &store.Alias{},
			},
			nullMask: []string{"Name"},
			want: &Alias{
				Alias: &store.Alias{
					ScopeId: "global",
					Value:   "test.alias",
				},
			},
		},
		{
			name: "update description",
			startingOptions: []Option{
				WithDescription("description"),
			},
			in: &Alias{
				Alias: &store.Alias{
					Description: "description-updated",
				},
			},
			fieldMask: []string{"Description"},
			want: &Alias{
				Alias: &store.Alias{
					ScopeId:     "global",
					Description: "description-updated",
					Value:       "test.alias",
				},
			},
		},
		{
			name: "remove description",
			startingOptions: []Option{
				WithDescription("description"),
			},
			in: &Alias{
				Alias: &store.Alias{},
			},
			nullMask: []string{"Description"},
			want: &Alias{
				Alias: &store.Alias{
					ScopeId: "global",
					Value:   "test.alias",
				},
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := TestAlias(t, rw, "test.alias", c.startingOptions...)
			t.Cleanup(func() {
				_, err := rw.Delete(ctx, a)
				require.NoError(t, err)
			})

			in := c.in.clone()
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
		a := TestAlias(t, rw, "alias.to.delete")
		n, err := rw.Delete(ctx, a)
		assert.NoError(t, err)
		assert.Equal(t, 1, n)
	})

	t.Run("delete existing with destination", func(t *testing.T) {
		_, p := iam.TestScopes(t, iam.TestRepo(t, conn, db.TestWrapper(t)))
		tar := tcp.TestTarget(ctx, t, conn, p.GetPublicId(), "test")
		a := TestAlias(t, rw, "alias.with.destination", WithDestinationId(tar.GetPublicId()))
		n, err := rw.Delete(ctx, a)
		assert.NoError(t, err)
		assert.Equal(t, 1, n)
	})

	t.Run("delete non-existent", func(t *testing.T) {
		a := allocAlias()
		a.PublicId = "alias_does_not_exist"
		n, err := rw.Delete(ctx, a)
		assert.NoError(t, err)
		assert.Equal(t, 0, n)
	})
}
