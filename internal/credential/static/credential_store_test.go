// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package static

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/internal/credential/static/store"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestCredentialStore_New(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	rw := db.New(conn)

	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))

	type args struct {
		projectId string
		opts      []Option
	}

	tests := []struct {
		name          string
		args          args
		want          *CredentialStore
		wantCreateErr bool
	}{
		{
			name:          "missing-project-id",
			want:          allocCredentialStore(),
			wantCreateErr: true,
		},
		{
			name: "valid-no-options",
			args: args{
				projectId: prj.PublicId,
			},
			want: &CredentialStore{
				CredentialStore: &store.CredentialStore{
					ProjectId: prj.PublicId,
				},
			},
		},
		{
			name: "valid-with-name",
			args: args{
				projectId: prj.PublicId,
				opts: []Option{
					WithName("test-name"),
				},
			},
			want: &CredentialStore{
				CredentialStore: &store.CredentialStore{
					ProjectId: prj.PublicId,
					Name:      "test-name",
				},
			},
		},
		{
			name: "valid-with-description",
			args: args{
				projectId: prj.PublicId,
				opts: []Option{
					WithDescription("test-description"),
				},
			},
			want: &CredentialStore{
				CredentialStore: &store.CredentialStore{
					ProjectId:   prj.PublicId,
					Description: "test-description",
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := NewCredentialStore(tt.args.projectId, tt.args.opts...)
			require.NoError(err)
			require.NotNil(got)

			assert.Emptyf(got.PublicId, "PublicId set")
			assert.Equal(tt.want, got)
			assert.Empty(cmp.Diff(tt.want, got.clone(), protocmp.Transform()))

			id, err := newCredentialStoreId(context.Background())
			assert.NoError(err)

			tt.want.PublicId = id
			got.PublicId = id

			err = rw.Create(context.Background(), got)
			if tt.wantCreateErr {
				require.Error(err)
				return
			}

			assert.NoError(err)
		})
	}
}
