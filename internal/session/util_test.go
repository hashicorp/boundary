// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package session

import (
	"context"
	"crypto/ed25519"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/libs/crypto"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeriveED25519Key(t *testing.T) {
	wrapper := db.TestWrapper(t)
	ctx := context.Background()

	type keys struct {
		pub  ed25519.PublicKey
		priv ed25519.PrivateKey
	}

	type args struct {
		wrapper wrapping.Wrapper
		userId  string
		jobId   string
	}
	tests := []struct {
		name        string
		args        args
		want        keys
		wantErr     bool
		wantErrCode errors.Code
	}{
		{
			name: "valid",
			args: args{
				wrapper: wrapper,
				userId:  "userId",
				jobId:   "jobId",
			},
			want: func() keys {
				reader, err := crypto.NewDerivedReader(ctx, wrapper, 32, []byte("userId"), []byte("jobId"))
				require.NoError(t, err)
				pub, priv, err := ed25519.GenerateKey(reader)
				require.NoError(t, err)
				return keys{pub: pub, priv: priv}
			}(),
		},
		{
			name: "nil-wrapper",
			args: args{
				wrapper: nil,
				userId:  "userId",
				jobId:   "jobId",
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			gotPub, gotPriv, err := DeriveED25519Key(ctx, tt.args.wrapper, tt.args.userId, tt.args.jobId)
			if tt.wantErr {
				require.Error(err)
				assert.Truef(errors.Match(errors.T(errors.InvalidParameter), err), "unexpected error: %s", err)
				assert.Nil(gotPub)
				assert.Nil(gotPriv)
				return
			}
			require.NoError(err)
			assert.Equalf(tt.want.pub, gotPub, "gotPub = %v, want %v", gotPub, tt.want.pub)
			assert.Equalf(tt.want.priv, gotPriv, "gotPriv = %v, want %v", gotPriv, tt.want.priv)
		})
	}
}
