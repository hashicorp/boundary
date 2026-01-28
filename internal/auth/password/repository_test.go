// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package password

import (
	"context"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRepository_New(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")

	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	testReader := strings.NewReader("notrandom")

	type args struct {
		r    db.Reader
		w    db.Writer
		kms  *kms.Kms
		opts []Option
	}

	tests := []struct {
		name       string
		args       args
		want       *Repository
		wantIsErr  errors.Code
		wantErrMsg string
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
				randomReader: rand.Reader,
			},
		},
		{
			name: "valid with limit",
			args: args{
				r:   rw,
				w:   rw,
				kms: kmsCache,
				opts: []Option{
					WithLimit(5),
					WithRandomReader(testReader),
				},
			},
			want: &Repository{
				reader:       rw,
				writer:       rw,
				kms:          kmsCache,
				defaultLimit: 5,
				randomReader: testReader,
			},
		},
		{
			name: "nil-reader",
			args: args{
				r:   nil,
				w:   rw,
				kms: kmsCache,
			},
			want:       nil,
			wantIsErr:  errors.InvalidParameter,
			wantErrMsg: "password.NewRepository: missing db.Reader: parameter violation: error #100",
		},
		{
			name: "nil-writer",
			args: args{
				r:   rw,
				w:   nil,
				kms: kmsCache,
			},
			want:       nil,
			wantIsErr:  errors.InvalidParameter,
			wantErrMsg: "password.NewRepository: missing db.Writer: parameter violation: error #100",
		},
		{
			name: "nil-wrapper",
			args: args{
				r:   rw,
				w:   rw,
				kms: nil,
			},
			want:       nil,
			wantIsErr:  errors.InvalidParameter,
			wantErrMsg: "password.NewRepository: missing kms: parameter violation: error #100",
		},
		{
			name: "all-nils",
			args: args{
				r:   nil,
				w:   nil,
				kms: nil,
			},
			want:       nil,
			wantIsErr:  errors.InvalidParameter,
			wantErrMsg: "password.NewRepository: missing db.Reader: parameter violation: error #100",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := NewRepository(context.Background(), tt.args.r, tt.args.w, tt.args.kms, tt.args.opts...)
			if tt.wantIsErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantIsErr), err), "Unexpected error %s", err)
				assert.Equal(tt.wantErrMsg, err.Error())
				return
			}
			assert.NoError(err)
			require.NotNil(got)
			assert.Equal(tt.want, got)
		})
	}
}
