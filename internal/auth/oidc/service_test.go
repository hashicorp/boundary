package oidc

import (
	"context"
	"testing"
	"time"

	"github.com/golang/protobuf/ptypes"
	"github.com/hashicorp/boundary/internal/auth/oidc/request"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func Test_encryptState(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rootWrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, rootWrapper)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, rootWrapper))
	databaseWrapper, err := kmsCache.GetWrapper(ctx, org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)
	testAuthMethod := TestAuthMethod(t, conn, databaseWrapper, org.PublicId, ActivePrivateState, TestConvertToUrls(t, "https://www.alice.com")[0], "alice-rp", "fido")

	now := time.Now()
	createTime, err := ptypes.TimestampProto(now.Truncate(time.Second))
	require.NoError(t, err)
	exp, err := ptypes.TimestampProto(now.Add(AttemptExpiration).Truncate(time.Second))
	require.NoError(t, err)

	tests := []struct {
		name         string
		wrapper      wrapping.Wrapper
		authMethod   *AuthMethod
		reqState     *request.State
		wantErrMatch *errors.Template
	}{
		{
			name:       "valid",
			wrapper:    db.TestWrapper(t),
			authMethod: testAuthMethod,
			reqState: &request.State{
				TokenRequestId:     "test-token-request-id",
				CreateTime:         &timestamp.Timestamp{Timestamp: createTime},
				ExpirationTime:     &timestamp.Timestamp{Timestamp: exp},
				Nonce:              "test-nonce",
				FinalRedirectUrl:   "www.alice.com/final",
				ProviderConfigHash: 100,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			encrypted, err := encryptState(ctx, tt.wrapper, tt.authMethod, tt.reqState)
			if tt.wantErrMatch != nil {
				require.Error(err)
				assert.Truef(errors.Match(tt.wantErrMatch, err), "want err code: %q got: %q", tt.wantErrMatch, err)
				assert.Empty(encrypted)
			}
			require.NoError(err)
			assert.NotEmpty(encrypted)

			gotScopeId, gotAuthMethodId, reqState, err := decryptState(ctx, tt.wrapper, encrypted)
			require.NoError(err)
			assert.Equalf(tt.authMethod.PublicId, gotAuthMethodId, "expected auth method %s and got: %s", tt.authMethod.PublicId, gotAuthMethodId)
			assert.Equalf(tt.authMethod.ScopeId, gotScopeId, "expected scope id %s and got: %s", tt.authMethod.ScopeId, gotScopeId)
			assert.True(proto.Equal(tt.reqState, reqState))
		})
	}

}
