package password

import (
	"errors"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRepository_New(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")

	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)

	type args struct {
		r    db.Reader
		w    db.Writer
		kms  *kms.Kms
		opts []Option
	}

	var tests = []struct {
		name      string
		args      args
		want      *Repository
		wantIsErr error
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
			name: "valid with limit",
			args: args{
				r:    rw,
				w:    rw,
				kms:  kmsCache,
				opts: []Option{WithLimit(5)},
			},
			want: &Repository{
				reader:       rw,
				writer:       rw,
				kms:          kmsCache,
				defaultLimit: 5,
			},
		},
		{
			name: "nil-reader",
			args: args{
				r:   nil,
				w:   rw,
				kms: kmsCache,
			},
			want:      nil,
			wantIsErr: db.ErrNilParameter,
		},
		{
			name: "nil-writer",
			args: args{
				r:   rw,
				w:   nil,
				kms: kmsCache,
			},
			want:      nil,
			wantIsErr: db.ErrNilParameter,
		},
		{
			name: "nil-wrapper",
			args: args{
				r:   rw,
				w:   rw,
				kms: nil,
			},
			want:      nil,
			wantIsErr: db.ErrNilParameter,
		},
		{
			name: "all-nils",
			args: args{
				r:   nil,
				w:   nil,
				kms: nil,
			},
			want:      nil,
			wantIsErr: db.ErrNilParameter,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := NewRepository(tt.args.r, tt.args.w, tt.args.kms, tt.args.opts...)
			if tt.wantIsErr != nil {
				assert.Truef(errors.Is(err, tt.wantIsErr), "want err: %q got: %q", tt.wantIsErr, err)
				assert.Nil(got)
				return
			}
			assert.NoError(err)
			require.NotNil(got)
			assert.Equal(tt.want, got)
		})
	}
}
