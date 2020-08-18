package static

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/host/static/store"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestHostCatalog_ImmutableFields(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	w := db.New(conn)

	_, proj := iam.TestScopes(t, conn)
	ts := timestamp.Timestamp{Timestamp: &timestamppb.Timestamp{Seconds: 0, Nanos: 0}}
	_, prj := iam.TestScopes(t, conn)
	new := testCatalog(t, conn, prj.PublicId)

	var tests = []struct {
		name      string
		update    *HostCatalog
		fieldMask []string
	}{
		{
			name: "public_id",
			update: func() *HostCatalog {
				c := new.clone()
				c.PublicId = "hc_thisIsNotAValidId"
				return c
			}(),
			fieldMask: []string{"PublicId"},
		},
		{
			name: "create time",
			update: func() *HostCatalog {
				c := new.clone()
				c.CreateTime = &ts
				return c
			}(),
			fieldMask: []string{"CreateTime"},
		},
		{
			name: "scope id",
			update: func() *HostCatalog {
				c := new.clone()
				c.ScopeId = proj.PublicId
				return c
			}(),
			fieldMask: []string{"ScopeId"},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			orig := new.clone()
			err := w.LookupById(context.Background(), orig)
			require.NoError(err)

			rowsUpdated, err := w.Update(context.Background(), tt.update, tt.fieldMask, nil)
			require.Error(err)
			assert.Equal(0, rowsUpdated)

			after := new.clone()
			err = w.LookupById(context.Background(), after)
			require.NoError(err)

			assert.True(proto.Equal(orig, after))

		})
	}
}

func TestStaticHost_ImmutableFields(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	w := db.New(conn)

	ts := timestamp.Timestamp{Timestamp: &timestamppb.Timestamp{Seconds: 0, Nanos: 0}}
	_, prj := iam.TestScopes(t, conn)
	cat := testCatalog(t, conn, prj.PublicId)
	hosts := testHosts(t, conn, cat.GetPublicId(), 1)

	new := hosts[0]

	var tests = []struct {
		name      string
		update    *Host
		fieldMask []string
	}{
		{
			name: "public_id",
			update: func() *Host {
				c := new.testCloneHost()
				c.PublicId = "hc_thisIsNotAValidId"
				return c
			}(),
			fieldMask: []string{"PublicId"},
		},
		{
			name: "create time",
			update: func() *Host {
				c := new.testCloneHost()
				c.CreateTime = &ts
				return c
			}(),
			fieldMask: []string{"CreateTime"},
		},
		{
			name: "static_host_catalog_id",
			update: func() *Host {
				c := new.testCloneHost()
				c.CatalogId = "stc_01234567890"
				return c
			}(),
			fieldMask: []string{"CatalogId"},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			orig := new.testCloneHost()
			err := w.LookupById(context.Background(), orig)
			require.NoError(err)

			rowsUpdated, err := w.Update(context.Background(), tt.update, tt.fieldMask, nil)
			require.Error(err)
			assert.Equal(0, rowsUpdated)

			after := new.testCloneHost()
			err = w.LookupById(context.Background(), after)
			require.NoError(err)

			assert.True(proto.Equal(orig, after))

		})
	}
}

func (c *Host) testCloneHost() *Host {
	cp := proto.Clone(c.Host)
	return &Host{
		Host: cp.(*store.Host),
	}
}

func TestStaticHostSet_ImmutableFields(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	w := db.New(conn)

	ts := timestamp.Timestamp{Timestamp: &timestamppb.Timestamp{Seconds: 0, Nanos: 0}}
	_, prj := iam.TestScopes(t, conn)
	cat := testCatalog(t, conn, prj.PublicId)
	sets := testSets(t, conn, cat.GetPublicId(), 1)

	new := sets[0]

	var tests = []struct {
		name      string
		update    *HostSet
		fieldMask []string
	}{
		{
			name: "public_id",
			update: func() *HostSet {
				c := new.testCloneHostSet()
				c.PublicId = "hc_thisIsNotAValidId"
				return c
			}(),
			fieldMask: []string{"PublicId"},
		},
		{
			name: "create time",
			update: func() *HostSet {
				c := new.testCloneHostSet()
				c.CreateTime = &ts
				return c
			}(),
			fieldMask: []string{"CreateTime"},
		},
		{
			name: "static_host_catalog_id",
			update: func() *HostSet {
				c := new.testCloneHostSet()
				c.CatalogId = "stc_01234567890"
				return c
			}(),
			fieldMask: []string{"CatalogId"},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			orig := new.testCloneHostSet()
			err := w.LookupById(context.Background(), orig)
			require.NoError(err)

			rowsUpdated, err := w.Update(context.Background(), tt.update, tt.fieldMask, nil)
			require.Error(err)
			assert.Equal(0, rowsUpdated)

			after := new.testCloneHostSet()
			err = w.LookupById(context.Background(), after)
			require.NoError(err)

			assert.True(proto.Equal(orig, after))

		})
	}
}

func (c *HostSet) testCloneHostSet() *HostSet {
	cp := proto.Clone(c.HostSet)
	return &HostSet{
		HostSet: cp.(*store.HostSet),
	}
}

func TestStaticHostSetMember_ImmutableFields(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	w := db.New(conn)

	_, prj := iam.TestScopes(t, conn)
	cat := testCatalog(t, conn, prj.PublicId)
	sets := testSets(t, conn, cat.GetPublicId(), 1)
	hosts := testHosts(t, conn, cat.GetPublicId(), 1)

	new, err := NewHostSetMember(sets[0].PublicId, hosts[0].PublicId)
	require.NoError(t, err)
	err = w.Create(context.Background(), new)
	assert.NoError(t, err)

	var tests = []struct {
		name      string
		update    *HostSetMember
		fieldMask []string
	}{
		{
			name: "set_id",
			update: func() *HostSetMember {
				c := new.testCloneHostSetMember()
				c.HostId = "shs_thisIsNotAValidId"
				return c
			}(),
			fieldMask: []string{"SetId"},
		},
		{
			name: "host_id",
			update: func() *HostSetMember {
				c := new.testCloneHostSetMember()
				c.HostId = "sth_01234567890"
				return c
			}(),
			fieldMask: []string{"HostId"},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			orig := new.testCloneHostSetMember()
			err = w.LookupWhere(context.Background(), orig, "host_id = ? and set_id = ?", orig.HostId, orig.SetId)
			require.NoError(err)

			rowsUpdated, err := w.Update(context.Background(), tt.update, tt.fieldMask, nil)
			require.Error(err)
			assert.Equal(0, rowsUpdated)

			after := new.testCloneHostSetMember()
			err = w.LookupWhere(context.Background(), after, "host_id = ? and set_id = ?", after.HostId, after.SetId)
			require.NoError(err)

			assert.True(proto.Equal(orig, after))

		})
	}
}

func (c *HostSetMember) testCloneHostSetMember() *HostSetMember {
	cp := proto.Clone(c.HostSetMember)
	return &HostSetMember{
		HostSetMember: cp.(*store.HostSetMember),
	}
}
