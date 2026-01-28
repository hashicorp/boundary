// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package target

import (
	"context"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/perms"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewRepository(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, conn, wrapper)
	testReader := strings.NewReader("notrandom")

	type args struct {
		r    db.Reader
		w    db.Writer
		kms  *kms.Kms
		opts []Option
	}
	tests := []struct {
		name          string
		args          args
		want          *Repository
		wantErr       bool
		wantErrString string
	}{
		{
			name: "valid",
			args: args{
				r:   rw,
				w:   rw,
				kms: testKms,
			},
			want: &Repository{
				reader:       rw,
				writer:       rw,
				kms:          testKms,
				defaultLimit: db.DefaultLimit,
				randomReader: rand.Reader,
			},
			wantErr: false,
		},
		{
			name: "nil-kms",
			args: args{
				r:   rw,
				w:   rw,
				kms: nil,
			},
			want:          nil,
			wantErr:       true,
			wantErrString: "target.NewRepository: nil kms: parameter violation: error #100",
		},
		{
			name: "nil-writer",
			args: args{
				r:   rw,
				w:   nil,
				kms: testKms,
			},
			want:          nil,
			wantErr:       true,
			wantErrString: "target.NewRepository: nil writer: parameter violation: error #100",
		},
		{
			name: "nil-reader",
			args: args{
				r:   nil,
				w:   rw,
				kms: testKms,
				opts: []Option{
					WithRandomReader(testReader),
				},
			},
			want:          nil,
			wantErr:       true,
			wantErrString: "target.NewRepository: nil reader: parameter violation: error #100",
		},
		{
			name: "WithPermissions sets object to `permissions`",
			args: args{
				r:   rw,
				w:   rw,
				kms: testKms,
				opts: []Option{
					WithPermissions([]perms.Permission{
						{GrantScopeId: "test1", Resource: resource.Target},
						{GrantScopeId: "test2", Resource: resource.Target},
					}),
					WithRandomReader(testReader),
				},
			},
			want: &Repository{
				reader:       rw,
				writer:       rw,
				kms:          testKms,
				defaultLimit: db.DefaultLimit,
				permissions: []perms.Permission{
					{GrantScopeId: "test1", Resource: resource.Target},
					{GrantScopeId: "test2", Resource: resource.Target},
				},
				randomReader: testReader,
			},
			wantErr: false,
		},
		{
			name: "Don't accept permissions that aren't for the Target resource",
			args: args{
				r:   rw,
				w:   rw,
				kms: testKms,
				opts: []Option{
					WithPermissions([]perms.Permission{
						{GrantScopeId: "test1", Resource: resource.Target},
						{GrantScopeId: "test2", Resource: resource.Host},
					}),
				},
			},
			want:          nil,
			wantErr:       true,
			wantErrString: "target.NewRepository: permission for incorrect resource found: parameter violation: error #100",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := NewRepository(context.Background(), tt.args.r, tt.args.w, tt.args.kms, tt.args.opts...)
			if tt.wantErr {
				require.Error(err)
				assert.Equal(tt.wantErrString, err.Error())
				return
			}
			require.NoError(err)
			assert.NotNil(got)
			assert.Equal(tt.want, got)
		})
	}
}

func Test_listTargetsRefresh(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, conn, wrapper)
	repo, err := NewRepository(context.Background(), rw, rw, testKms)
	require.NoError(t, err)
	t.Run("missing updated after", func(t *testing.T) {
		t.Parallel()
		_, _, err := repo.listTargetsRefresh(context.Background(), time.Time{})
		require.ErrorContains(t, err, "missing updated after")
	})
}
