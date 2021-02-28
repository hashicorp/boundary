package oidc

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/go-kms-wrapping/wrappers/aead"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewRepository(t *testing.T) {
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
	tests := []struct {
		name         string
		args         args
		want         *Repository
		wantErrMatch *errors.Template
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
			want:         nil,
			wantErrMatch: errors.T(errors.InvalidParameter),
		},
		{
			name: "nil-writer",
			args: args{
				r:   rw,
				w:   nil,
				kms: kmsCache,
			},
			want:         nil,
			wantErrMatch: errors.T(errors.InvalidParameter),
		},
		{
			name: "nil-wrapper",
			args: args{
				r:   rw,
				w:   rw,
				kms: nil,
			},
			want:         nil,
			wantErrMatch: errors.T(errors.InvalidParameter),
		},
		{
			name: "all-nils",
			args: args{
				r:   nil,
				w:   nil,
				kms: nil,
			},
			want:         nil,
			wantErrMatch: errors.T(errors.InvalidParameter),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := NewRepository(tt.args.r, tt.args.w, tt.args.kms, tt.args.opts...)
			if tt.wantErrMatch != nil {
				require.Error(err)
				assert.Truef(errors.Match(tt.wantErrMatch, err), "want err code: %q got: %q", tt.wantErrMatch, err)
				assert.Nil(got)
				return
			}
			require.NoError(err)
			require.NotNil(got)
			assert.Equal(tt.want, got)
		})
	}
}

func TestRepository_stateWrapper(t *testing.T) {
	t.Parallel()
	ctx := context.TODO()
	conn, _ := db.TestSetup(t, "postgres")
	rootWrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, rootWrapper)

	rw := db.New(conn)
	repo, err := NewRepository(rw, rw, kmsCache)
	require.NoError(t, err)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, rootWrapper))
	databaseWrapper, err := kmsCache.GetWrapper(ctx, org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)
	testAuthMethod := TestAuthMethod(t, conn, databaseWrapper, org.PublicId, ActivePrivateState, TestConvertToUrls(t, "https://alice.com")[0], "alice-rp", "fido")

	oidcWrapper, err := kmsCache.GetWrapper(ctx, org.PublicId, kms.KeyPurposeOidc)
	require.NoError(t, err)

	tests := []struct {
		name         string
		setupFn      func() (string, string)
		opt          []Option
		wantErrMatch *errors.Template
	}{
		{
			name:    "simple-valid",
			setupFn: func() (string, string) { return org.PublicId, testAuthMethod.PublicId },
		},
		{
			name:         "missing-scope",
			setupFn:      func() (string, string) { return "", testAuthMethod.PublicId },
			wantErrMatch: errors.T(errors.InvalidParameter),
		},
		{
			name:         "missing-auth-method-id",
			setupFn:      func() (string, string) { return org.PublicId, "" },
			wantErrMatch: errors.T(errors.InvalidParameter),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			scopeId, authMethodId := tt.setupFn()

			wantKeyId := derivedKeyId(derivedKeyPurposeState, oidcWrapper.KeyID(), authMethodId)
			kmsCache.GetDerivedPurposeCache().Delete(wantKeyId)

			stateWrapper, err := repo.stateWrapper(ctx, scopeId, authMethodId, tt.opt...)
			if tt.wantErrMatch != nil {
				require.Error(err)
				assert.Empty(stateWrapper)
				cachedWrapper, found := kmsCache.GetDerivedPurposeCache().Load(wantKeyId)
				assert.False(found)
				assert.Empty(cachedWrapper)
				return
			}
			require.NoError(err)
			assert.NotEmpty(stateWrapper)
			assert.Equalf(wantKeyId, stateWrapper.KeyID(), "expected key id %s and got: %s", wantKeyId, stateWrapper.KeyID())
			assert.Equalf(wrapping.AEAD, stateWrapper.Type(), "expected type %s and got: %s", wrapping.AEAD, stateWrapper.Type())
			assert.NotEmpty(stateWrapper.(*aead.Wrapper).GetKeyBytes())

			cachedWrapper, found := kmsCache.GetDerivedPurposeCache().Load(wantKeyId)
			require.True(found)
			require.NotEmpty(cachedWrapper)
			assert.Equal(stateWrapper, cachedWrapper)

			dupWrapper, err := repo.stateWrapper(ctx, scopeId, authMethodId, tt.opt...)
			require.NoError(err)
			require.NotEmpty(dupWrapper)
			assert.Equal(stateWrapper, dupWrapper)
		})
	}
}

func Test_derivedKeyPurpose_String(t *testing.T) {

	tests := []struct {
		purpose derivedKeyPurpose
		want    string
	}{
		{100, "oidc_unknown"},
		{derivedKeyPurposeUnknown, "oidc_unknown"},
		{derivedKeyPurposeState, "oidc_state"},
	}
	for _, tt := range tests {
		t.Run(tt.purpose.String(), func(t *testing.T) {
			assert.Equalf(t, tt.want, tt.purpose.String(), "wanted %s and got: %s", tt.want, tt.purpose.String())
		})
	}

}
