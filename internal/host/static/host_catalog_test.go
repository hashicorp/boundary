package static

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/host/static/store"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/jinzhu/gorm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHostCatalog_New(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
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

func TestHostCatalog_SetTableName(t *testing.T) {
	defaultTableName := "static_host_catalog"
	tests := []struct {
		name        string
		initialName string
		setNameTo   string
		want        string
	}{
		{
			name:        "new-name",
			initialName: "",
			setNameTo:   "new-name",
			want:        "new-name",
		},
		{
			name:        "reset to default",
			initialName: "initial",
			setNameTo:   "",
			want:        defaultTableName,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			def := allocCatalog()
			require.Equal(defaultTableName, def.TableName())
			s := &HostCatalog{
				HostCatalog: &store.HostCatalog{},
				tableName:   tt.initialName,
			}
			s.SetTableName(tt.setNameTo)
			assert.Equal(tt.want, s.TableName())
		})
	}
}
