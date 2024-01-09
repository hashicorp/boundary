// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package apptoken

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewRepository(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, conn, wrapper)
	testIamRepo := iam.TestRepo(t, conn, wrapper)
	type args struct {
		r   db.Reader
		w   db.Writer
		kms *kms.Kms
		gf  grantFinder
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
				gf:  testIamRepo,
			},
			want: &Repository{
				reader:       rw,
				writer:       rw,
				kms:          testKms,
				grantFinder:  testIamRepo,
				defaultLimit: db.DefaultLimit,
			},
			wantErr: false,
		},
		{
			name: "nil-kms",
			args: args{
				r:   rw,
				w:   rw,
				kms: nil,
				gf:  testIamRepo,
			},
			want:          nil,
			wantErr:       true,
			wantErrString: "apptoken.NewRepository: nil kms: parameter violation: error #100",
		},
		{
			name: "nil-writer",
			args: args{
				r:   rw,
				w:   nil,
				kms: testKms,
				gf:  testIamRepo,
			},
			want:          nil,
			wantErr:       true,
			wantErrString: "apptoken.NewRepository: nil writer: parameter violation: error #100",
		},
		{
			name: "nil-reader",
			args: args{
				r:   nil,
				w:   rw,
				kms: testKms,
				gf:  testIamRepo,
			},
			want:          nil,
			wantErr:       true,
			wantErrString: "apptoken.NewRepository: nil reader: parameter violation: error #100",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := NewRepository(context.Background(), tt.args.r, tt.args.w, tt.args.kms, tt.args.gf)
			if tt.wantErr {
				require.Error(err)
				assert.Equal(tt.wantErrString, err.Error())
				return
			}
			require.NoError(err)
			assert.Equal(tt.want, got)
		})
	}
}

func TestRepository_ResolveUserHistoryId(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, conn, wrapper)
	testIamRepo := iam.TestRepo(t, conn, wrapper)
	testOrg, _ := iam.TestScopes(t, testIamRepo)
	testUser := iam.TestUser(t, testIamRepo, testOrg.GetPublicId())

	testcases := []struct {
		name            string
		userId          string
		wantErrContains string
	}{
		{
			name:   "valid",
			userId: testUser.PublicId,
		},
		{
			name:            "missing-user-id",
			wantErrContains: "missing user id",
		},
		{
			name:            "user-id-not-exists",
			userId:          "fake-user-id",
			wantErrContains: "record not found",
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			r, err := NewRepository(context.Background(), rw, rw, testKms, testIamRepo)
			require.NoError(err)

			_, err = r.ResolveUserHistoryId(context.Background(), tc.userId)
			if tc.wantErrContains != "" {
				require.Errorf(err, "we expected an error")
				assert.Contains(err.Error(), tc.wantErrContains)
				return
			}
			require.NoErrorf(err, "unexpected error")
		})
	}
}
