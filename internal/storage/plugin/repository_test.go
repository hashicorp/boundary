// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package plugin

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/scheduler"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRepository_NewRepository(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	sche := scheduler.TestScheduler(t, conn, wrapper)

	tests := []struct {
		name            string
		in              *Repository
		want            *Repository
		wantErrContains string
		wantErrCode     errors.Code
	}{
		{
			name: "no-reader",
			in: &Repository{
				writer: rw,
				kms:    kmsCache,
			},
			wantErrContains: "nil db.Reader",
			wantErrCode:     errors.InvalidParameter,
		},
		{
			name: "no-writer",
			in: &Repository{
				reader: rw,
				kms:    kmsCache,
			},
			wantErrContains: "nil db.Writer",
			wantErrCode:     errors.InvalidParameter,
		},
		{
			name: "no-kms",
			in: &Repository{
				reader: rw,
				writer: rw,
			},
			wantErrContains: "nil kms",
			wantErrCode:     errors.InvalidParameter,
		},
		{
			name: "valid-repository",
			in: &Repository{
				reader: rw,
				writer: rw,
				kms:    kmsCache,
			},
			want: &Repository{
				reader: rw,
				writer: rw,
				kms:    kmsCache,
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			require, assert := require.New(t), assert.New(t)
			ctx := context.Background()

			repo, err := NewRepository(ctx, tt.in.reader, tt.in.writer, tt.in.kms, sche)
			if tt.wantErrContains != "" {
				require.ErrorContains(err, tt.wantErrContains)
				return
			}
			require.NoError(err)

			assert.Equal(tt.want.reader, repo.reader)
			assert.Equal(tt.want.writer, repo.writer)
			assert.Equal(tt.want.kms, repo.kms)
		})
	}
}
