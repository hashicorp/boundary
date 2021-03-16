package kms

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/types/scope"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/go-kms-wrapping/wrappers/aead"
	"github.com/hashicorp/go-uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/hkdf"
)

func TestKms_KeyId(t *testing.T) {
	t.Parallel()
	require := require.New(t)
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	extWrapper := db.TestWrapper(t)
	repo, err := NewRepository(rw, rw)
	require.NoError(err)

	// Make the global scope base keys
	_, err = CreateKeysTx(ctx, rw, rw, extWrapper, rand.Reader, scope.Global.String())
	require.NoError(err)

	// Get the global scope's root wrapper
	kmsCache, err := NewKms(repo)
	require.NoError(err)
	require.NoError(kmsCache.AddExternalWrappers(WithRootWrapper(extWrapper)))
	globalRootWrapper, _, err := kmsCache.loadRoot(ctx, scope.Global.String())
	require.NoError(err)

	dks, err := repo.ListDatabaseKeys(ctx)
	require.NoError(err)
	require.Len(dks, 1)

	// Create another key version
	newKeyBytes, err := uuid.GenerateRandomBytes(32)
	require.NoError(err)
	_, err = repo.CreateDatabaseKeyVersion(ctx, globalRootWrapper, dks[0].GetPrivateId(), newKeyBytes)
	require.NoError(err)

	dkvs, err := repo.ListDatabaseKeyVersions(ctx, globalRootWrapper, dks[0].GetPrivateId())
	require.NoError(err)
	require.Len(dkvs, 2)

	keyId1 := dkvs[0].GetPrivateId()
	keyId2 := dkvs[1].GetPrivateId()

	// First test: just getting the key should return the latest
	wrapper, err := kmsCache.GetWrapper(ctx, scope.Global.String(), KeyPurposeDatabase)
	require.NoError(err)
	require.Equal(keyId2, wrapper.KeyID())

	// Second: ask for each in turn
	wrapper, err = kmsCache.GetWrapper(ctx, scope.Global.String(), KeyPurposeDatabase, WithKeyId(keyId1))
	require.NoError(err)
	require.Equal(keyId1, wrapper.KeyID())
	wrapper, err = kmsCache.GetWrapper(ctx, scope.Global.String(), KeyPurposeDatabase, WithKeyId(keyId2))
	require.NoError(err)
	require.Equal(keyId2, wrapper.KeyID())

	// Last: verify something bogus finds nothing
	_, err = kmsCache.GetWrapper(ctx, scope.Global.String(), KeyPurposeDatabase, WithKeyId("foo"))
	require.Error(err)
}

func TestNewDerivedReader(t *testing.T) {
	wrapper := db.TestWrapper(t)

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
		wantErrCode     errors.Code
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
			wantErrCode:     errors.InvalidParameter,
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
			wantErrCode:     errors.InvalidParameter,
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
			wantErrCode:     errors.InvalidParameter,
			wantErrContains: "missing bytes",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := NewDerivedReader(tt.args.wrapper, tt.args.lenLimit, tt.args.salt, tt.args.info)
			if tt.wantErr {
				require.Error(err)
				assert.Truef(errors.Match(errors.T(errors.InvalidParameter), err), "unexpected error: %s", err)
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
