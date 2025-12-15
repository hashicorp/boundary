// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package plugin

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/host/plugin/store"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestHostSet_Create(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	plg := plugin.TestPlugin(t, conn, "test")
	cat := TestCatalog(t, conn, prj.PublicId, plg.GetPublicId())
	cat2 := TestCatalog(t, conn, prj.PublicId, plg.GetPublicId())

	type args struct {
		catalogId string
		opts      []Option
	}

	tests := []struct {
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
			want: &HostSet{HostSet: &store.HostSet{
				Attributes: []byte{},
			}},
			wantErr: true,
		},
		{
			name: "valid-no-options",
			args: args{
				catalogId: cat.GetPublicId(),
			},
			want: &HostSet{
				HostSet: &store.HostSet{
					CatalogId:  cat.GetPublicId(),
					Attributes: []byte{},
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
					CatalogId:  cat.GetPublicId(),
					Name:       "test-name",
					Attributes: []byte{},
				},
			},
		},
		{
			name: "duplicate-name",
			args: args{
				catalogId: cat.GetPublicId(),
				opts: []Option{
					WithName("test-name"),
				},
			},
			want: &HostSet{
				HostSet: &store.HostSet{
					CatalogId:  cat.GetPublicId(),
					Name:       "test-name",
					Attributes: []byte{},
				},
			},
			wantErr: true,
		},
		{
			name: "valid-duplicate-name-different-catalog",
			args: args{
				catalogId: cat2.GetPublicId(),
				opts: []Option{
					WithName("test-name"),
				},
			},
			want: &HostSet{
				HostSet: &store.HostSet{
					CatalogId:  cat2.GetPublicId(),
					Name:       "test-name",
					Attributes: []byte{},
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
					Attributes:  []byte{},
				},
			},
		},
		{
			name: "valid-with-attributes",
			args: args{
				catalogId: cat.GetPublicId(),
				opts: []Option{
					WithAttributes(&structpb.Struct{Fields: map[string]*structpb.Value{"foo": structpb.NewStringValue("bar")}}),
				},
			},
			want: &HostSet{
				HostSet: &store.HostSet{
					CatalogId: cat.GetPublicId(),
					Attributes: func() []byte {
						st := &structpb.Struct{Fields: map[string]*structpb.Value{"foo": structpb.NewStringValue("bar")}}
						b, err := proto.Marshal(st)
						require.NoError(t, err)
						return b
					}(),
				},
			},
		},
		{
			name: "valid-with-preferred-endpoints",
			args: args{
				catalogId: cat.GetPublicId(),
				opts: []Option{
					WithPreferredEndpoints([]string{"cidr:1.2.3.4"}),
				},
			},
			want: &HostSet{
				HostSet: &store.HostSet{
					CatalogId:  cat.GetPublicId(),
					Attributes: []byte{},
				},
				PreferredEndpoints: []string{"cidr:1.2.3.4"},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			got, err := NewHostSet(ctx, tt.args.catalogId, tt.args.opts...)
			require.NoError(t, err)
			require.NotNil(t, got)
			assert.Emptyf(t, got.PublicId, "PublicId set")
			assert.Equal(t, tt.want, got)

			id, err := newHostSetId(ctx)
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

func TestHostSet_SetTableName(t *testing.T) {
	defaultTableName := "host_plugin_set"
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
