// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

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
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres", db.WithTestLogLevel(t, db.SilentTestLogLevel))
	wrapper := db.TestWrapper(t)
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	cat := testCatalog(t, conn, prj.PublicId)

	type args struct {
		catalogId string
		opts      []Option
	}

	tests := []struct {
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
				opts:      []Option{WithAddress("12")},
			},
			want: &Host{
				Host: &store.Host{
					CatalogId: cat.GetPublicId(),
					Address:   "12",
				},
			},
			wantWriteErr: true,
		},
		{
			name: "minimum-address",
			args: args{
				catalogId: cat.GetPublicId(),
				opts:      []Option{WithAddress("123")},
			},
			want: &Host{
				Host: &store.Host{
					CatalogId: cat.GetPublicId(),
					Address:   "123",
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
			require, assert := require.New(t), assert.New(t)
			got, err := NewHost(ctx, tt.args.catalogId, tt.args.opts...)
			if tt.wantCreateErr {
				require.Error(err)
				assert.Nil(got)
				return
			}
			require.NoError(err)
			require.NotNil(got)
			assert.Emptyf(got.PublicId, "PublicId set")
			assert.Equal(tt.want, got)

			id, err := newHostId(ctx)
			require.NoError(err)
			tt.want.PublicId = id
			got.PublicId = id

			w := db.New(conn)
			dbWriteErr := w.Create(ctx, got)
			if tt.wantWriteErr {
				require.Error(dbWriteErr)
				return
			}
			require.NoError(dbWriteErr)
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
