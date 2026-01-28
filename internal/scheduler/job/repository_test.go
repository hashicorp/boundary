// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package job

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRepository_New(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)

	type args struct {
		r   db.Reader
		w   db.Writer
		kms *kms.Kms
	}

	tests := []struct {
		name        string
		args        args
		opts        []Option
		want        *Repository
		wantErr     bool
		wantErrCode errors.Code
		wantErrMsg  string
	}{
		{
			name: "valid",
			args: args{
				r:   rw,
				w:   rw,
				kms: kmsCache,
			},
			want: &Repository{
				reader:       rw,
				writer:       rw,
				kms:          kmsCache,
				defaultLimit: db.DefaultLimit,
			},
		},
		{
			name: "valid-with-limit",
			args: args{
				r:   rw,
				w:   rw,
				kms: kmsCache,
			},
			opts: []Option{
				WithLimit(10),
			},
			want: &Repository{
				reader:       rw,
				writer:       rw,
				kms:          kmsCache,
				defaultLimit: 10,
			},
		},
		{
			name: "nil-reader",
			args: args{
				r:   nil,
				w:   rw,
				kms: kmsCache,
			},
			want:        nil,
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
			wantErrMsg:  "job.NewRepository: missing db reader: parameter violation: error #100",
		},
		{
			name: "nil-writer",
			args: args{
				r:   rw,
				w:   nil,
				kms: kmsCache,
			},
			want:        nil,
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
			wantErrMsg:  "job.NewRepository: missing db writer: parameter violation: error #100",
		},
		{
			name: "nil-kms",
			args: args{
				r:   rw,
				w:   rw,
				kms: nil,
			},
			want:        nil,
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
			wantErrMsg:  "job.NewRepository: missing kms: parameter violation: error #100",
		},
		{
			name: "all-nils",
			args: args{
				r:   nil,
				w:   nil,
				kms: nil,
			},
			want:        nil,
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
			wantErrMsg:  "job.NewRepository: missing db reader: parameter violation: error #100",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := NewRepository(context.Background(), tt.args.r, tt.args.w, tt.args.kms, tt.opts...)
			if tt.wantErr {
				require.Error(err)
				assert.Truef(errors.Match(errors.T(tt.wantErrCode), err), "Unexpected error %s", err)
				assert.Equal(tt.wantErrMsg, err.Error())
				return
			}
			assert.NoError(err)
			assert.NotNil(got)
			assert.Equal(tt.want, got)
		})
	}
}
