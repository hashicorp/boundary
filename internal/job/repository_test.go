package job

import (
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/stretchr/testify/assert"
)

func TestRepository_New(t *testing.T) {
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
				reader: rw,
				writer: rw,
				kms:    kmsCache,
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
			assert := assert.New(t)
			got, err := NewRepository(tt.args.r, tt.args.w, tt.args.kms)
			if tt.wantErr {
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
