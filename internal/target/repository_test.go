package target

import (
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/perms"
	"github.com/hashicorp/boundary/internal/types/resource"
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
		r    db.Reader
		w    db.Writer
		kms  *kms.Kms
		opts []Option
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
			},
			want: &Repository{
				reader:       rw,
				writer:       rw,
				kms:          testKms,
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
			},
			want:          nil,
			wantErr:       true,
			wantErrString: "target.NewRepository: nil kms: parameter violation: error #100",
		},
		{
			name: "nil-writer",
			args: args{
				r:   rw,
				w:   nil,
				kms: testKms,
			},
			want:          nil,
			wantErr:       true,
			wantErrString: "target.NewRepository: nil writer: parameter violation: error #100",
		},
		{
			name: "nil-reader",
			args: args{
				r:   nil,
				w:   rw,
				kms: testKms,
			},
			want:          nil,
			wantErr:       true,
			wantErrString: "target.NewRepository: nil reader: parameter violation: error #100",
		},
		{
			name: "WithPermissions sets object to `permissions`",
			args: args{
				r:   rw,
				w:   rw,
				kms: testKms,
				opts: []Option{
					WithPermissions([]perms.Permission{
						{ScopeId: "test1", Resource: resource.Target},
						{ScopeId: "test2", Resource: resource.Target},
					}),
				},
			},
			want: &Repository{
				reader:       rw,
				writer:       rw,
				kms:          testKms,
				defaultLimit: db.DefaultLimit,
				permissions: []perms.Permission{
					{ScopeId: "test1", Resource: resource.Target},
					{ScopeId: "test2", Resource: resource.Target},
				},
			},
			wantErr: false,
		},
		{
			name: "Don't accept permissions that aren't for the Target resource",
			args: args{
				r:   rw,
				w:   rw,
				kms: testKms,
				opts: []Option{
					WithPermissions([]perms.Permission{
						{ScopeId: "test1", Resource: resource.Target},
						{ScopeId: "test2", Resource: resource.Host},
					}),
				},
			},
			want:          nil,
			wantErr:       true,
			wantErrString: "target.NewRepository: permission for incorrect resource found: parameter violation: error #100",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := NewRepository(tt.args.r, tt.args.w, tt.args.kms, tt.args.opts...)
			if tt.wantErr {
				require.Error(err)
				assert.Equal(tt.wantErrString, err.Error())
				return
			}
			require.NoError(err)
			assert.NotNil(got)
			assert.Equal(tt.want, got)
		})
	}
}
