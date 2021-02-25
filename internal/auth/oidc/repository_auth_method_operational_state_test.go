package oidc

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/cap/oidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_MakeInactive(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)

	tp := oidc.StartTestProvider(t)
	tpClientId := "alice-rp"
	tpClientSecret := "her-dog's-name"
	tp.SetClientCreds(tpClientId, tpClientSecret)
	_, _, tpAlg, _ := tp.SigningKeys()
	tpCert, err := ParseCertificates(tp.CACert())
	require.NoError(t, err)
	require.Equal(t, 1, len(tpCert))

	rw := db.New(conn)
	repo, err := NewRepository(rw, rw, kmsCache)
	require.NoError(t, err)

	tests := []struct {
		name         string
		operateOn    string
		wantErrMatch *errors.Template
	}{
		{
			name: "ActivePrivate-to-InActive",
			operateOn: func() string {
				org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
				databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
				require.NoError(t, err)
				return TestAuthMethod(t,
					conn, databaseWrapper,
					org.PublicId,
					ActivePrivateState,
					TestConvertToUrls(t, tp.Addr())[0],
					"alice-rp", "alice-secret",
					WithCertificates(tpCert[0]),
					WithSigningAlgs(Alg(tpAlg)),
					WithCallbackUrls(TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
				).PublicId
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			err := repo.MakeInactive(ctx, tt.operateOn)
			if tt.wantErrMatch != nil {
				require.Error(err)
				assert.Truef(errors.Match(tt.wantErrMatch, err), "want err code: %q got: %q", tt.wantErrMatch.Code, err)

				err := db.TestVerifyOplog(t, rw, tt.operateOn, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second))
				require.Errorf(err, "should not have found oplog entry for %s", tt.operateOn)
			}
			require.NoError(err)
			found, err := repo.LookupAuthMethod(ctx, tt.operateOn)
			require.NoError(err)
			require.NotEmpty(found)
			assert.Equal(string(InactiveState), found.OperationalState)

			err = db.TestVerifyOplog(t, rw, tt.operateOn, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second))
			require.NoErrorf(err, "unexpected error verifying oplog entry: %s", err)
		})
	}

}
