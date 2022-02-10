package crypto

import (
	"crypto/sha256"
	"io"
	"testing"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-kms-wrapping/wrappers/aead/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/hkdf"
)

func TestNewDerivedReader(t *testing.T) {
	wrapper := TestWrapper(t)

	type args struct {
		wrapper  wrapping.Wrapper
		lenLimit int64
		salt     []byte
		info     []byte
	}
	tests := []struct {
		name            string
		args            args
		want            *io.LimitedReader
		wantErr         bool
		wantErrCode     error
		wantErrContains string
	}{
		{
			name: "valid-with-salt",
			args: args{
				wrapper:  wrapper,
				lenLimit: 32,
				info:     nil,
				salt:     []byte("salt"),
			},
			want: &io.LimitedReader{
				R: hkdf.New(sha256.New, wrapper.(*aead.Wrapper).GetKeyBytes(), []byte("salt"), nil),
				N: 32,
			},
		},
		{
			name: "valid-with-salt-info",
			args: args{
				wrapper:  wrapper,
				lenLimit: 32,
				info:     []byte("info"),
				salt:     []byte("salt"),
			},
			want: &io.LimitedReader{
				R: hkdf.New(sha256.New, wrapper.(*aead.Wrapper).GetKeyBytes(), []byte("salt"), []byte("info")),
				N: 32,
			},
		},
		{
			name: "nil-wrapper",
			args: args{
				wrapper:  nil,
				lenLimit: 10,
				info:     []byte("info"),
				salt:     []byte("salt"),
			},
			wantErr:         true,
			wantErrCode:     ErrInvalidParameter,
			wantErrContains: "missing wrapper",
		},
		{
			name: "too-short",
			args: args{
				wrapper:  wrapper,
				lenLimit: 10,
				info:     []byte("info"),
				salt:     []byte("salt"),
			},
			wantErr:         true,
			wantErrCode:     ErrInvalidParameter,
			wantErrContains: "lenLimit must be >= 20",
		},
		{
			name: "wrapper-with-no-bytes",
			args: args{
				wrapper:  &aead.Wrapper{},
				lenLimit: 32,
				info:     nil,
				salt:     []byte("salt"),
			},
			wantErr:         true,
			wantErrCode:     ErrInvalidParameter,
			wantErrContains: "missing bytes",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := NewDerivedReader(tt.args.wrapper, tt.args.lenLimit, tt.args.salt, tt.args.info)
			if tt.wantErr {
				require.Error(err)
				assert.ErrorIsf(err, tt.wantErrCode, "unexpected error: %s", err)
				if tt.wantErrContains != "" {
					assert.Contains(err.Error(), tt.wantErrContains)
				}
				return
			}
			require.NoError(err)
			assert.Equal(tt.want, got)
		})
	}
}
