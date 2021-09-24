package plugin

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/host/plugin/store"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/plugin/host"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHost_Create(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	plg := host.TestPlugin(t, conn, "test")
	cat := TestCatalog(t, conn, prj.PublicId, plg.GetPublicId())
	cat2 := TestCatalog(t, conn, prj.PublicId, plg.GetPublicId())

	type args struct {
		catalogId string
		address   string
		opts      []Option
	}

	tests := []struct {
		name    string
		args    args
		want    *Host
		wantErr bool
	}{
		{
			name: "blank-catalogId",
			args: args{
				catalogId: "",
				address:   "foo.bar.com",
			},
			want: &Host{Host: &store.Host{
				Address: "foo.bar.com",
			}},
			wantErr: true,
		},
		{
			name: "blank-address",
			args: args{
				catalogId: cat.GetPublicId(),
			},
			want: &Host{Host: &store.Host{
				CatalogId: cat.GetPublicId(),
			}},
			wantErr: true,
		},
		{
			name: "valid-no-options",
			args: args{
				catalogId: cat.GetPublicId(),
				address:   "foo.bar.com",
			},
			want: &Host{
				Host: &store.Host{
					CatalogId: cat.GetPublicId(),
					Address:   "foo.bar.com",
				},
			},
		},
		{
			name: "valid-with-name",
			args: args{
				catalogId: cat.GetPublicId(),
				address:   "foo.bar.com",
				opts: []Option{
					WithName("test-name"),
				},
			},
			want: &Host{
				Host: &store.Host{
					CatalogId: cat.GetPublicId(),
					Address:   "foo.bar.com",
					Name:      "test-name",
				},
			},
		},
		{
			name: "duplicate-name",
			args: args{
				catalogId: cat.GetPublicId(),
				address:   "foo.bar.com",
				opts: []Option{
					WithName("test-name"),
				},
			},
			want: &Host{
				Host: &store.Host{
					CatalogId: cat.GetPublicId(),
					Address:   "foo.bar.com",
					Name:      "test-name",
				},
			},
			wantErr: true,
		},
		{
			name: "valid-duplicate-name-different-catalog",
			args: args{
				catalogId: cat2.GetPublicId(),
				address:   "foo.bar.com",
				opts: []Option{
					WithName("test-name"),
				},
			},
			want: &Host{
				Host: &store.Host{
					CatalogId: cat2.GetPublicId(),
					Address:   "foo.bar.com",
					Name:      "test-name",
				},
			},
		},
		{
			name: "valid-with-description",
			args: args{
				catalogId: cat.GetPublicId(),
				address:   "foo.bar.com",
				opts: []Option{
					WithDescription("test-description"),
				},
			},
			want: &Host{
				Host: &store.Host{
					CatalogId:   cat.GetPublicId(),
					Address:     "foo.bar.com",
					Description: "test-description",
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			got := newHost(ctx, tt.args.catalogId, tt.args.address, tt.args.opts...)
			require.NotNil(t, got)
			assert.Emptyf(t, got.PublicId, "PublicId set")
			assert.Equal(t, tt.want, got)

			id, err := newHostId(ctx, tt.name, tt.name)
			assert.NoError(t, err)

			tt.want.PublicId = id
			got.PublicId = id

			w := db.New(conn)
			err = w.Create(context.Background(), got)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestHost_SetTableName(t *testing.T) {
	defaultTableName := "host_plugin_host"
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
