// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package servers

import (
	"context"
	"crypto/rand"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/server"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/nodeenrollment/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRotateRootsJob(t *testing.T) {
	require, assert := require.New(t), assert.New(t)
	ctx := context.Background()
	wrapper := db.TestWrapper(t)
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	kmsCache := kms.TestKms(t, conn, wrapper)
	err := kmsCache.CreateKeys(context.Background(), scope.Global.String(), kms.WithRandomReader(rand.Reader))
	require.NoError(err)

	workerAuthRepo, err := server.NewRepositoryStorage(ctx, rw, rw, kmsCache)
	require.NoError(err)

	type args struct {
		w   db.Writer
		r   db.Reader
		kms *kms.Kms
	}
	tests := []struct {
		name        string
		args        args
		options     []server.Option
		wantLimit   int
		wantErr     bool
		wantErrCode errors.Code
	}{
		{
			name: "nil writer",
			args: args{
				r:   rw,
				kms: kmsCache,
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
		},
		{
			name: "nil reader",
			args: args{
				w:   rw,
				kms: kmsCache,
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
		},
		{
			name: "nil kms",
			args: args{
				w: rw,
				r: rw,
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
		},
		{
			name: "valid",
			args: args{
				w:   rw,
				r:   rw,
				kms: kmsCache,
			},
			wantLimit: db.DefaultLimit,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := newRotateRootsJob(ctx, tt.args.r, tt.args.w, tt.args.kms)
			if tt.wantErr {
				require.Error(err)
				assert.Nil(got)
				assert.Truef(errors.Match(errors.T(tt.wantErrCode), err), "Unexpected error %s", err)
				return
			}
			require.NoError(err)
			require.NotNil(got)
			require.Equal(0, got.totalRotates)
			rootIds, err := workerAuthRepo.List(ctx, (*types.RootCertificate)(nil))
			require.NoError(err)
			assert.Len(rootIds, 0)
			assert.Equal("rotate_roots", got.Name())
			assert.Equal("Rotate root certificates", got.Description())
			nextRun, err := got.NextRunIn(ctx)
			require.NoError(err)
			assert.Equal(time.Hour, nextRun)

			// Run job and ensure rotation was performed
			err = got.Run(ctx, 0)
			require.NoError(err)
			require.Equal(1, got.totalRotates)
			rootIds, err = workerAuthRepo.List(ctx, (*types.RootCertificate)(nil))
			require.NoError(err)
			assert.Len(rootIds, 2)
		})
	}
}

func TestRotateRootsJobFailure(t *testing.T) {
	require := require.New(t)
	ctx := context.Background()
	wrapper := db.TestWrapper(t)
	conn, _ := db.TestSetup(t, "postgres")
	kmsCache := kms.TestKms(t, conn, wrapper)
	err := kmsCache.CreateKeys(context.Background(), scope.Global.String(), kms.WithRandomReader(rand.Reader))
	require.NoError(err)

	got, err := newRotateRootsJob(ctx, &db.Db{}, &db.Db{}, kmsCache)
	require.NoError(err)

	err = got.Run(ctx, 0)
	require.Error(err)
}
