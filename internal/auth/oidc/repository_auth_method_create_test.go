package oidc

import (
	"context"
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRepository_CreateAuthMethod(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	ctx := context.Background()
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))

	tests := []struct {
		name         string
		am           *AuthMethod
		opt          []Option
		wantErrMatch *errors.Template
	}{
		{
			name: "valid",
			am: func() *AuthMethod {
				am, err := NewAuthMethod(
					org.PublicId,
					TestConvertToUrls(t, "https://www.alice.com")[0],
					"alice-rp",
					"alice-secret", WithAudClaims("alice-rp"),
					WithAudClaims("alice-rp", "bob-rp"),
					WithCallbackUrls(TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
					WithSigningAlgs(RS256, ES256),
					WithName("alice's restaurant"),
					WithDescription("it's a good place to eat"),
				)
				require.NoError(t, err)
				require.Equal(t, am.SigningAlgs, []string{string(RS256), string(ES256)})
				require.Equal(t, am.CallbackUrls, []string{"https://www.alice.com/callback"})
				require.Equal(t, am.AudClaims, []string{"alice-rp", "bob-rp"})
				return am
			}(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(rw, rw, kmsCache)
			assert.NoError(err)
			require.NotNil(repo)
			got, err := repo.CreateAuthMethod(ctx, tt.am, tt.opt...)
			if tt.wantErrMatch != nil {
				require.Error(err)
				assert.Truef(errors.Match(tt.wantErrMatch, err), "want err code: %q got: %q", tt.wantErrMatch, err)
				assert.Nil(got)
				return
			}
			require.NoError(err)
			tt.am.PublicId = got.PublicId
			tt.am.CreateTime = got.CreateTime
			tt.am.UpdateTime = got.UpdateTime
			tt.am.Version = got.Version
			assert.Truef(proto.Equal(tt.am.AuthMethod, got.AuthMethod), "got %+v expected %+v", got, tt.am)
		})
	}
}
