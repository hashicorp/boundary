package static

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/host/static/store"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHost_New(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	cat := testCatalog(t, conn, wrapper, prj.PublicId)

	conn.LogMode(false)
	type args struct {
		catalogId string
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
			},
			want:          nil,
			wantCreateErr: true,
		},
		{
			name: "blank-address",
			args: args{
				catalogId: cat.GetPublicId(),
			},
			want: &Host{
				Host: &store.Host{
					CatalogId: cat.GetPublicId(),
				},
			},
			wantWriteErr: true,
		},
		{
			name: "address-to-short",
			args: args{
				catalogId: cat.GetPublicId(),
				opts:      []Option{WithAddress("1234567")},
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
				opts:      []Option{WithAddress("12345678")},
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
			},
			want: &Host{
				Host: &store.Host{
					CatalogId: cat.GetPublicId(),
				},
			},
			wantWriteErr: true,
		},
		{
			name: "valid-with-name",
			args: args{
				catalogId: cat.GetPublicId(),
				opts: []Option{
					WithAddress("127.0.0.1"),
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
				opts: []Option{
					WithAddress("127.0.0.1"),
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
			got, err := NewHost(tt.args.catalogId, tt.args.opts...)
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
