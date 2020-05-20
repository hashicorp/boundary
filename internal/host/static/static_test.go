package static

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/host/static/store"
	"github.com/hashicorp/watchtower/internal/iam"
	"github.com/jinzhu/gorm"
	"github.com/stretchr/testify/assert"
)

func TestHostCatalog_New(t *testing.T) {
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer cleanup()
	defer conn.Close()

	_, prj := iam.TestScopes(t, conn)

	type args struct {
		scopeId string
		opts    []Option
	}

	var tests = []struct {
		name    string
		args    args
		want    *HostCatalog
		wantErr bool
	}{
		{
			name: "blank-scopeId",
			args: args{
				scopeId: "",
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "valid-no-options",
			args: args{
				scopeId: prj.GetPublicId(),
			},
			want: &HostCatalog{
				HostCatalog: &store.HostCatalog{
					ScopeId: prj.GetPublicId(),
				},
			},
		},
		{
			name: "valid-with-name",
			args: args{
				scopeId: prj.GetPublicId(),
				opts: []Option{
					WithName("test-name"),
				},
			},
			want: &HostCatalog{
				HostCatalog: &store.HostCatalog{
					ScopeId: prj.GetPublicId(),
					Name:    "test-name",
				},
			},
		},
		{
			name: "valid-with-description",
			args: args{
				scopeId: prj.GetPublicId(),
				opts: []Option{
					WithDescription("test-description"),
				},
			},
			want: &HostCatalog{
				HostCatalog: &store.HostCatalog{
					ScopeId:     prj.GetPublicId(),
					Description: "test-description",
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			got, err := NewHostCatalog(tt.args.scopeId, tt.args.opts...)
			if tt.wantErr {
				assert.Error(err)
				assert.Nil(got)
			} else {
				assert.NoError(err)
				if assert.NotNil(got) {
					assert.Emptyf(got.PublicId, "PublicId set")
					assert.Equal(tt.want, got)

					id, err := newHostCatalogId()
					assert.NoError(err)

					tt.want.PublicId = id
					got.PublicId = id

					w := db.New(conn)
					err2 := w.Create(context.Background(), got)
					assert.NoError(err2)
				}
			}
		})
	}
}

func testCatalogs(t *testing.T, conn *gorm.DB, count int) []*HostCatalog {
	t.Helper()
	assert := assert.New(t)
	_, prj := iam.TestScopes(t, conn)
	var cats []*HostCatalog
	for i := 0; i < count; i++ {
		cat, err := NewHostCatalog(prj.GetPublicId())
		assert.NoError(err)
		assert.NotNil(cat)
		id, err := newHostCatalogId()
		assert.NoError(err)
		assert.NotEmpty(id)
		cat.PublicId = id

		w := db.New(conn)
		err2 := w.Create(context.Background(), cat)
		assert.NoError(err2)
		cats = append(cats, cat)
	}
	return cats
}

func testCatalog(t *testing.T, conn *gorm.DB) *HostCatalog {
	t.Helper()
	cats := testCatalogs(t, conn, 1)
	return cats[0]
}

func TestHost_New(t *testing.T) {
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer cleanup()
	defer conn.Close()
	cat := testCatalog(t, conn)

	conn.LogMode(false)
	type args struct {
		catalogId string
		address   string
		opts      []Option
	}

	var tests = []struct {
		name          string
		args          args
		want          *Host
		wantCreateErr bool
		wantWriteErr  bool
	}{
		{
			name: "blank-catalogId",
			args: args{
				catalogId: "",
				address:   "127.0.0.1",
			},
			want:          nil,
			wantCreateErr: true,
		},
		{
			name: "blank-address",
			args: args{
				catalogId: cat.GetPublicId(),
				address:   "",
			},
			want:          nil,
			wantCreateErr: true,
		},
		{
			name: "address-to-short",
			args: args{
				catalogId: cat.GetPublicId(),
				address:   "1234567",
			},
			want: &Host{
				Host: &store.Host{
					StaticHostCatalogId: cat.GetPublicId(),
					Address:             "1234567",
				},
			},
			wantWriteErr: true,
		},
		{
			name: "minimum-address",
			args: args{
				catalogId: cat.GetPublicId(),
				address:   "12345678",
			},
			want: &Host{
				Host: &store.Host{
					StaticHostCatalogId: cat.GetPublicId(),
					Address:             "12345678",
				},
			},
		},
		{
			name: "valid-no-options",
			args: args{
				catalogId: cat.GetPublicId(),
				address:   "127.0.0.1",
			},
			want: &Host{
				Host: &store.Host{
					StaticHostCatalogId: cat.GetPublicId(),
					Address:             "127.0.0.1",
				},
			},
		},
		{
			name: "valid-with-name",
			args: args{
				catalogId: cat.GetPublicId(),
				address:   "127.0.0.1",
				opts: []Option{
					WithName("test-name"),
				},
			},
			want: &Host{
				Host: &store.Host{
					StaticHostCatalogId: cat.GetPublicId(),
					Address:             "127.0.0.1",
					Name:                "test-name",
				},
			},
		},
		{
			name: "valid-with-description",
			args: args{
				catalogId: cat.GetPublicId(),
				address:   "127.0.0.1",
				opts: []Option{
					WithDescription("test-description"),
				},
			},
			want: &Host{
				Host: &store.Host{
					StaticHostCatalogId: cat.GetPublicId(),
					Address:             "127.0.0.1",
					Description:         "test-description",
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			got, err := NewHost(tt.args.catalogId, tt.args.address, tt.args.opts...)
			if tt.wantCreateErr {
				assert.Error(err)
				assert.Nil(got)
			} else {
				assert.NoError(err)
				if assert.NotNil(got) {
					assert.Emptyf(got.PublicId, "PublicId set")
					assert.Equal(tt.want, got)

					id, err := newHostId()
					assert.NoError(err)

					tt.want.PublicId = id
					got.PublicId = id

					w := db.New(conn)
					err2 := w.Create(context.Background(), got)
					if tt.wantWriteErr {
						assert.Error(err2)
					}
				}
			}
		})
	}
}

func TestHostSet_New(t *testing.T) {
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer cleanup()
	defer conn.Close()
	cat := testCatalog(t, conn)

	conn.LogMode(false)
	type args struct {
		catalogId string
		opts      []Option
	}

	var tests = []struct {
		name    string
		args    args
		want    *HostSet
		wantErr bool
	}{
		{
			name: "blank-catalogId",
			args: args{
				catalogId: "",
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "valid-no-options",
			args: args{
				catalogId: cat.GetPublicId(),
			},
			want: &HostSet{
				HostSet: &store.HostSet{
					StaticHostCatalogId: cat.GetPublicId(),
				},
			},
		},
		{
			name: "valid-with-name",
			args: args{
				catalogId: cat.GetPublicId(),
				opts: []Option{
					WithName("test-name"),
				},
			},
			want: &HostSet{
				HostSet: &store.HostSet{
					StaticHostCatalogId: cat.GetPublicId(),
					Name:                "test-name",
				},
			},
		},
		{
			name: "valid-with-description",
			args: args{
				catalogId: cat.GetPublicId(),
				opts: []Option{
					WithDescription("test-description"),
				},
			},
			want: &HostSet{
				HostSet: &store.HostSet{
					StaticHostCatalogId: cat.GetPublicId(),
					Description:         "test-description",
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			got, err := NewHostSet(tt.args.catalogId, tt.args.opts...)
			if tt.wantErr {
				assert.Error(err)
				assert.Nil(got)
			} else {
				assert.NoError(err)
				if assert.NotNil(got) {
					assert.Emptyf(got.PublicId, "PublicId set")
					assert.Equal(tt.want, got)

					id, err := newHostSetId()
					assert.NoError(err)

					tt.want.PublicId = id
					got.PublicId = id

					w := db.New(conn)
					err2 := w.Create(context.Background(), got)
					assert.NoError(err2)
				}
			}
		})
	}
}

func testHosts(t *testing.T, conn *gorm.DB, catalogId string, count int) []*Host {
	t.Helper()
	assert := assert.New(t)
	var hosts []*Host

	for i := 0; i < count; i++ {
		host, err := NewHost(catalogId, fmt.Sprintf("%s-%d", catalogId, i))
		assert.NoError(err)
		assert.NotNil(host)

		id, err := newHostCatalogId()
		assert.NoError(err)
		assert.NotEmpty(id)
		host.PublicId = id

		w := db.New(conn)
		err2 := w.Create(context.Background(), host)
		assert.NoError(err2)
		hosts = append(hosts, host)
	}
	return hosts
}

func testSets(t *testing.T, conn *gorm.DB, catalogId string, count int) []*HostSet {
	t.Helper()
	assert := assert.New(t)
	var sets []*HostSet

	for i := 0; i < count; i++ {
		set, err := NewHostSet(catalogId)
		assert.NoError(err)
		assert.NotNil(set)
		id, err := newHostSetId()
		assert.NoError(err)
		assert.NotEmpty(id)
		set.PublicId = id

		w := db.New(conn)
		err2 := w.Create(context.Background(), set)
		assert.NoError(err2)
		sets = append(sets, set)
	}
	return sets
}

func TestHostSetMember_New(t *testing.T) {
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer cleanup()
	defer conn.Close()
	conn.LogMode(false)

	cats := testCatalogs(t, conn, 2)

	blueCat := cats[0]
	blueSets := testSets(t, conn, blueCat.GetPublicId(), 2)
	blueHosts := testHosts(t, conn, blueCat.GetPublicId(), 2)

	// these will be needed when the repository code is done
	// greenCat := cats[1]
	// greenSets := testSets(t, conn, greenCat.GetPublicId(), 2)
	// greenHosts := testHosts(t, conn, greenCat.GetPublicId(), 2)

	var tests = []struct {
		name    string
		set     *HostSet
		host    *Host
		wantErr bool
	}{
		{
			name: "valid-host-in-set",
			set:  blueSets[0],
			host: blueHosts[0],
		},
		// {
		// 	name:    "invalid-diff-catalogs",
		// 	set:     greenSets[0],
		// 	host:    blueHosts[0],
		// 	wantErr: true,
		// },
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			got, err := NewHostSetMember(tt.set.PublicId, tt.host.PublicId)
			if tt.wantErr {
				assert.Error(err)
				assert.Nil(got)
			} else {
				assert.NoError(err)
				if assert.NotNil(got) {
					w := db.New(conn)
					err2 := w.Create(context.Background(), got)
					assert.NoError(err2)
				}
			}
		})
	}
}
