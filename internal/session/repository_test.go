package session

import (
	"testing"

	"github.com/hashicorp/boundary/internal/db"
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

	type args struct {
		r db.Reader
		w db.Writer
		k *kms.Kms
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
				r: rw,
				w: rw,
				k: testKms,
			},
			want: func() *Repository {
				ret, err := NewRepository(rw, rw, testKms)
				require.NoError(t, err)
				return ret
			}(),
			wantErr: false,
		},
		{
			name: "nil-writer",
			args: args{
				r: rw,
				w: nil,
			},
			want:          nil,
			wantErr:       true,
			wantErrString: "session.NewRepository: nil writer: parameter violation: error #100",
		},
		{
			name: "nil-reader",
			args: args{
				r: nil,
				w: rw,
			},
			want:          nil,
			wantErr:       true,
			wantErrString: "session.NewRepository: nil reader: parameter violation: error #100",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := NewRepository(tt.args.r, tt.args.w, tt.args.k)
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
