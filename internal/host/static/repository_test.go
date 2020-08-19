package static

import (
	"errors"
	"testing"

	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/hashicorp/boundary/internal/db"
)

func TestRepository_New(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)

	type args struct {
		r       db.Reader
		w       db.Writer
		wrapper wrapping.Wrapper
		opts    []Option
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
				r:       rw,
				w:       rw,
				wrapper: wrapper,
			},
			want: &Repository{
				reader:       rw,
				writer:       rw,
				wrapper:      wrapper,
				defaultLimit: db.DefaultLimit,
			},
		},
		{
			name: "valid-with-limit",
			args: args{
				r:       rw,
				w:       rw,
				wrapper: wrapper,
				opts:    []Option{WithLimit(5)},
			},
			want: &Repository{
				reader:       rw,
				writer:       rw,
				wrapper:      wrapper,
				defaultLimit: 5,
			},
		},
		{
			name: "nil-reader",
			args: args{
				r:       nil,
				w:       rw,
				wrapper: wrapper,
			},
			want:      nil,
			wantIsErr: db.ErrNilParameter,
		},
		{
			name: "nil-writer",
			args: args{
				r:       rw,
				w:       nil,
				wrapper: wrapper,
			},
			want:      nil,
			wantIsErr: db.ErrNilParameter,
		},
		{
			name: "nil-wrapper",
			args: args{
				r:       rw,
				w:       rw,
				wrapper: nil,
			},
			want:      nil,
			wantIsErr: db.ErrNilParameter,
		},
		{
			name: "all-nils",
			args: args{
				r:       nil,
				w:       nil,
				wrapper: nil,
			},
			want:      nil,
			wantIsErr: db.ErrNilParameter,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := NewRepository(tt.args.r, tt.args.w, tt.args.wrapper, tt.args.opts...)
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
