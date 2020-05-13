package static

import (
	"context"
	"strings"
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
					assertPublicID(t, "sthc", got.PublicId)
					tt.want.PublicId = got.PublicId
					assert.Equal(tt.want, got)
					w := db.New(conn)
					err2 := w.Create(context.Background(), got)
					assert.NoError(err2)
				}
			}
		})
	}
}

func testCatalog(t *testing.T, conn *gorm.DB) *HostCatalog {
	t.Helper()
	assert := assert.New(t)
	_, prj := iam.TestScopes(t, conn)
	cat, err := NewHostCatalog(prj.GetPublicId())
	assert.NoError(err)
	assert.NotNil(cat)

	w := db.New(conn)
	err2 := w.Create(context.Background(), cat)
	assert.NoError(err2)
	return cat
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
					assertPublicID(t, "sth", got.PublicId)
					tt.want.PublicId = got.PublicId
					assert.Equal(tt.want, got)
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

func assertPublicID(t *testing.T, prefix, actual string) {
	t.Helper()
	if actual == "" {
		t.Errorf("PublicId is empty")
	}
	parts := strings.Split(actual, "_")
	switch {
	case len(parts) > 2:
		t.Errorf("want one '_' in PublicID, got multiple in %q", actual)
	case len(parts) < 2:
		t.Errorf("want one '_' in PublicID, got none in %q", actual)
	}

	if prefix != parts[0] {
		t.Errorf("PublicID want prefix: %q, got: %q in %q", prefix, parts[0], actual)
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
					assertPublicID(t, "sths", got.PublicId)
					tt.want.PublicId = got.PublicId
					assert.Equal(tt.want, got)
					w := db.New(conn)
					err2 := w.Create(context.Background(), got)
					assert.NoError(err2)
				}
			}
		})
	}
}
