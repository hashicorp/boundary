// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"context"
	"crypto/sha256"
	"io"
	"testing"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-kms-wrapping/v2/aead"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/hkdf"
)

func TestNewDerivedReader(t *testing.T) {
	wrapper := TestWrapper(t)
	ctx := context.Background()

	type args struct {
		wrapper  wrapping.Wrapper
		lenLimit int64
		salt     []byte
		info     []byte
	}
	tests := []struct {
		name            string
		args            args
		want            func() *io.LimitedReader
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
			want: func() *io.LimitedReader {
				keyBytes, err := wrapper.(*aead.Wrapper).KeyBytes(ctx)
				if err != nil {
					t.Fatal(err)
				}
				return &io.LimitedReader{
					R: hkdf.New(sha256.New, keyBytes, []byte("salt"), nil),
					N: 32,
				}
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
			want: func() *io.LimitedReader {
				keyBytes, err := wrapper.(*aead.Wrapper).KeyBytes(ctx)
				if err != nil {
					t.Fatal(err)
				}
				return &io.LimitedReader{
					R: hkdf.New(sha256.New, keyBytes, []byte("salt"), []byte("info")),
					N: 32,
				}
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
			wantErrCode:     wrapping.ErrInvalidParameter,
			wantErrContains: "missing bytes",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := NewDerivedReader(ctx, tt.args.wrapper, tt.args.lenLimit, tt.args.salt, tt.args.info)
			if tt.wantErr {
				require.Error(err)
				assert.ErrorIsf(err, tt.wantErrCode, "unexpected error: %s", err)
				if tt.wantErrContains != "" {
					assert.Contains(err.Error(), tt.wantErrContains)
				}
				return
			}
			require.NoError(err)
			assert.Equal(tt.want(), got)
		})
	}
}
