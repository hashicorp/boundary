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

func TestHostSet_New(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	cat := testCatalog(t, conn, prj.PublicId)

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
					CatalogId: cat.GetPublicId(),
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
					CatalogId: cat.GetPublicId(),
					Name:      "test-name",
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
					CatalogId:   cat.GetPublicId(),
					Description: "test-description",
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

func TestHostSet_SetTableName(t *testing.T) {
	defaultTableName := "static_host_set"
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
			def := &HostSet{
				HostSet: &store.HostSet{},
			}
			require.Equal(defaultTableName, def.TableName())
			s := &HostSet{
				HostSet:   &store.HostSet{},
				tableName: tt.initialName,
			}
			s.SetTableName(tt.setNameTo)
			assert.Equal(tt.want, s.TableName())
		})
	}
}
