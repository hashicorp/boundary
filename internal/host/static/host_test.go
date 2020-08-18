package static

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/host/static/store"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/jinzhu/gorm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHost_New(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	_, prj := iam.TestScopes(t, conn)
	cat := testCatalog(t, conn, prj.PublicId)

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
					CatalogId: cat.GetPublicId(),
					Address:   "1234567",
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
					CatalogId: cat.GetPublicId(),
					Address:   "12345678",
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
					CatalogId: cat.GetPublicId(),
					Address:   "127.0.0.1",
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
					CatalogId: cat.GetPublicId(),
					Address:   "127.0.0.1",
					Name:      "test-name",
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
					CatalogId:   cat.GetPublicId(),
					Address:     "127.0.0.1",
					Description: "test-description",
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

func TestHost_SetTableName(t *testing.T) {
	defaultTableName := "static_host"
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
			def := &Host{
				Host: &store.Host{},
			}
			require.Equal(defaultTableName, def.TableName())
			s := &Host{
				Host:      &store.Host{},
				tableName: tt.initialName,
			}
			s.SetTableName(tt.setNameTo)
			assert.Equal(tt.want, s.TableName())
		})
	}
}
