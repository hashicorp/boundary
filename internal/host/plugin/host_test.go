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
)

func TestHost_Create(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	plg := plugin.TestPlugin(t, conn, "test")
	cat := TestCatalog(t, conn, prj.PublicId, plg.GetPublicId())
	cat2 := TestCatalog(t, conn, prj.PublicId, plg.GetPublicId())

	type args struct {
		catalogId  string
		externalId string
		opts       []Option
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
				catalogId:  "",
				externalId: "external_id",
			},
			want: &Host{Host: &store.Host{
				ExternalId: "external_id",
			}},
			wantErr: true,
		},
		{
			name: "blank-external-id",
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
				catalogId:  cat.GetPublicId(),
				externalId: "valid-no-options",
			},
			want: &Host{
				Host: &store.Host{
					CatalogId:  cat.GetPublicId(),
					ExternalId: "valid-no-options",
				},
			},
		},
		{
			name: "valid-with-name",
			args: args{
				catalogId:  cat.GetPublicId(),
				externalId: "valid-with-name",
				opts: []Option{
					WithName("test-name"),
				},
			},
			want: &Host{
				Host: &store.Host{
					CatalogId:  cat.GetPublicId(),
					ExternalId: "valid-with-name",
					Name:       "test-name",
				},
			},
		},
		{
			name: "valid-duplicate-name-same-catalog",
			args: args{
				catalogId:  cat.GetPublicId(),
				externalId: "duplicate-name",
				opts: []Option{
					WithName("test-name"),
				},
			},
			want: &Host{
				Host: &store.Host{
					CatalogId:  cat.GetPublicId(),
					ExternalId: "duplicate-name",
					Name:       "test-name",
				},
			},
		},
		{
			name: "valid-duplicate-name-different-catalog",
			args: args{
				catalogId:  cat2.GetPublicId(),
				externalId: "valid-duplicate-name-different-catalog",
				opts: []Option{
					WithName("test-name"),
				},
			},
			want: &Host{
				Host: &store.Host{
					CatalogId:  cat2.GetPublicId(),
					ExternalId: "valid-duplicate-name-different-catalog",
					Name:       "test-name",
				},
			},
		},
		{
			name: "valid-with-description",
			args: args{
				catalogId:  cat.GetPublicId(),
				externalId: "valid-with-description",
				opts: []Option{
					WithDescription("test-description"),
				},
			},
			want: &Host{
				Host: &store.Host{
					CatalogId:   cat.GetPublicId(),
					ExternalId:  "valid-with-description",
					Description: "test-description",
				},
			},
		},
		{
			name: "valid-with-external-name",
			args: args{
				catalogId:  cat.GetPublicId(),
				externalId: "valid-with-external-name",
				opts: []Option{
					WithExternalName("valid-with-external-name"),
				},
			},
			want: &Host{
				Host: &store.Host{
					CatalogId:    cat.GetPublicId(),
					ExternalId:   "valid-with-external-name",
					ExternalName: "valid-with-external-name",
				},
			},
		},
		{
			name: "external-name-too-long",
			args: args{
				catalogId:  cat.GetPublicId(),
				externalId: "external-name-too-long",
				opts: []Option{
					WithExternalName(
						"this_is_a_string_with_32_chars__" +
							"this_is_a_string_with_32_chars__" +
							"this_is_a_string_with_32_chars__" +
							"this_is_a_string_with_32_chars__" +
							"this_is_a_string_with_32_chars__" +
							"this_is_a_string_with_32_chars__" +
							"this_is_a_string_with_32_chars__" +
							"this_is_a_string_with_32_chars__" +
							"_oops_too_many",
					),
				},
			},
			want: &Host{
				Host: &store.Host{
					CatalogId:    cat.GetPublicId(),
					ExternalId:   "external-name-too-long",
					ExternalName: "",
				},
			},
		},
		{
			name: "non-printable-external-name",
			args: args{
				catalogId:  cat.GetPublicId(),
				externalId: "non-printable-external-name",
				opts: []Option{
					WithExternalName("this_is_printable_but_this\u0000_and_this\u000D_isnt_"),
				},
			},
			want: &Host{
				Host: &store.Host{
					CatalogId:    cat.GetPublicId(),
					ExternalId:   "non-printable-external-name",
					ExternalName: "",
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			got := NewHost(ctx, tt.args.catalogId, tt.args.externalId, tt.args.opts...)
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

// TODO: Test Deletion directly of host, of set membership, and of cascading
//   from the set

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
