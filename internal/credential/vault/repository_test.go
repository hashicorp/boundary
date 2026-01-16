// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"context"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/scheduler"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRepository_New(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	sche := scheduler.TestScheduler(t, conn, wrapper)
	testReader := strings.NewReader("notrandom")

	type args struct {
		r         db.Reader
		w         db.Writer
		kms       *kms.Kms
		scheduler *scheduler.Scheduler
		opts      []Option
	}

	tests := []struct {
		name      string
		args      args
		want      *Repository
		wantIsErr errors.Code
	}{
		{
			name: "valid",
			args: args{
				r:         rw,
				w:         rw,
				kms:       kmsCache,
				scheduler: sche,
			},
			want: &Repository{
				reader:       rw,
				writer:       rw,
				kms:          kmsCache,
				scheduler:    sche,
				defaultLimit: db.DefaultLimit,
				randomReader: rand.Reader,
			},
		},
		{
			name: "valid-with-limit",
			args: args{
				r:         rw,
				w:         rw,
				kms:       kmsCache,
				scheduler: sche,
				opts: []Option{
					WithLimit(5),
					WithRandomReader(testReader),
				},
			},
			want: &Repository{
				reader:       rw,
				writer:       rw,
				kms:          kmsCache,
				scheduler:    sche,
				defaultLimit: 5,
				randomReader: testReader,
			},
		},
		{
			name: "nil-reader",
			args: args{
				r:         nil,
				w:         rw,
				kms:       kmsCache,
				scheduler: sche,
			},
			want:      nil,
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "nil-writer",
			args: args{
				r:         rw,
				w:         nil,
				kms:       kmsCache,
				scheduler: sche,
			},
			want:      nil,
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "nil-kms",
			args: args{
				r:         rw,
				w:         rw,
				kms:       nil,
				scheduler: sche,
			},
			want:      nil,
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "nil-scheduler",
			args: args{
				r:         rw,
				w:         rw,
				kms:       kmsCache,
				scheduler: nil,
			},
			want:      nil,
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "all-nils",
			args: args{
				r:         nil,
				w:         nil,
				kms:       nil,
				scheduler: nil,
			},
			want:      nil,
			wantIsErr: errors.InvalidParameter,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := NewRepository(context.Background(), tt.args.r, tt.args.w, tt.args.kms, tt.args.scheduler, tt.args.opts...)
			if tt.wantIsErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantIsErr), err), "want err: %q got: %q", tt.wantIsErr, err)
				assert.Nil(got)
				return
			}
			assert.NoError(err)
			require.NotNil(got)
			assert.Equal(tt.want, got)
		})
	}
}
