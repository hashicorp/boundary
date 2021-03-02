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

func Test_MakeInactive_MakePrivate_MakePublic(t *testing.T) {
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
		name            string
		toState         AuthMethodState
		operateOn       string
		wantErrMatch    *errors.Template
		wantErrContains string
		wantNoOplog     bool
	}{
		{
			name:    "ActivePrivate-to-InActive",
			toState: InactiveState,
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
		{
			name:    "ActivePublic-to-InActive",
			toState: InactiveState,
			operateOn: func() string {
				org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
				databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
				require.NoError(t, err)
				return TestAuthMethod(t,
					conn, databaseWrapper,
					org.PublicId,
					ActivePublicState,
					TestConvertToUrls(t, tp.Addr())[0],
					"alice-rp", "alice-secret",
					WithCertificates(tpCert[0]),
					WithSigningAlgs(Alg(tpAlg)),
					WithCallbackUrls(TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
				).PublicId
			}(),
		},
		{
			name:    "Inactive-to-Inactive",
			toState: InactiveState,
			operateOn: func() string {
				org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
				databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
				require.NoError(t, err)
				return TestAuthMethod(t,
					conn, databaseWrapper,
					org.PublicId,
					InactiveState,
					TestConvertToUrls(t, tp.Addr())[0],
					"alice-rp", "alice-secret",
					WithCertificates(tpCert[0]),
					WithSigningAlgs(Alg(tpAlg)),
					WithCallbackUrls(TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
				).PublicId
			}(),
			wantNoOplog: true,
		},
		{
			name:    "InActive-to-ActivePrivate",
			toState: ActivePrivateState,
			operateOn: func() string {
				org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
				databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
				require.NoError(t, err)
				return TestAuthMethod(t,
					conn, databaseWrapper,
					org.PublicId,
					InactiveState,
					TestConvertToUrls(t, tp.Addr())[0],
					"alice-rp", "alice-secret",
					WithCertificates(tpCert[0]),
					WithSigningAlgs(Alg(tpAlg)),
					WithCallbackUrls(TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
				).PublicId
			}(),
		},
		{
			name:    "ActivePublic-to-ActivePrivate",
			toState: ActivePrivateState,
			operateOn: func() string {
				org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
				databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
				require.NoError(t, err)
				return TestAuthMethod(t,
					conn, databaseWrapper,
					org.PublicId,
					ActivePublicState,
					TestConvertToUrls(t, tp.Addr())[0],
					"alice-rp", "alice-secret",
					WithCertificates(tpCert[0]),
					WithSigningAlgs(Alg(tpAlg)),
					WithCallbackUrls(TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
				).PublicId
			}(),
		},
		{
			name:    "ActivePrivate-to-ActivePrivate",
			toState: ActivePrivateState,
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
			wantNoOplog: true,
		},
		{
			name:    "InActive-to-ActivePublic",
			toState: ActivePublicState,
			operateOn: func() string {
				org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
				databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
				require.NoError(t, err)
				return TestAuthMethod(t,
					conn, databaseWrapper,
					org.PublicId,
					InactiveState,
					TestConvertToUrls(t, tp.Addr())[0],
					"alice-rp", "alice-secret",
					WithCertificates(tpCert[0]),
					WithSigningAlgs(Alg(tpAlg)),
					WithCallbackUrls(TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
				).PublicId
			}(),
		},
		{
			name:    "ActivePrivate-to-ActivePublic",
			toState: ActivePublicState,
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
		{
			name:    "ActivePublic-to-ActivePublic",
			toState: ActivePublicState,
			operateOn: func() string {
				org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
				databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
				require.NoError(t, err)
				return TestAuthMethod(t,
					conn, databaseWrapper,
					org.PublicId,
					ActivePublicState,
					TestConvertToUrls(t, tp.Addr())[0],
					"alice-rp", "alice-secret",
					WithCertificates(tpCert[0]),
					WithSigningAlgs(Alg(tpAlg)),
					WithCallbackUrls(TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
				).PublicId
			}(),
			wantNoOplog: true,
		},
		{
			name:    "force-InActive-to-ActivePrivate",
			toState: ActivePrivateState,
			operateOn: func() string {
				org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
				databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
				require.NoError(t, err)
				// the returned oidc auth method is incomplete
				return TestAuthMethod(t,
					conn, databaseWrapper,
					org.PublicId,
					InactiveState,
					TestConvertToUrls(t, tp.Addr())[0],
					"alice-rp", "alice-secret",
				).PublicId
			}(),
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "unable to transition from inactive",
		},
		{
			name:    "force-InActive-to-ActivePublic",
			toState: ActivePublicState,
			operateOn: func() string {
				org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
				databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
				require.NoError(t, err)
				// the returned oidc auth method is incomplete
				return TestAuthMethod(t,
					conn, databaseWrapper,
					org.PublicId,
					InactiveState,
					TestConvertToUrls(t, tp.Addr())[0],
					"alice-rp", "alice-secret",
				).PublicId
			}(),
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "unable to transition from inactive",
		},
		{
			name:            "missing-auth-method-id",
			toState:         InactiveState,
			operateOn:       "",
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing auth method id",
		},
		{
			name:            "not-found",
			toState:         InactiveState,
			operateOn:       "not-found-auth-method-id",
			wantErrMatch:    errors.T(errors.RecordNotFound),
			wantErrContains: "auth method not found",
		},
		{
			name:    "error-for-InActive-to-ActivePrivate",
			toState: ActivePrivateState,
			operateOn: func() string {
				org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
				databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
				require.NoError(t, err)
				// the returned oidc auth method is incomplete
				return TestAuthMethod(t,
					conn, databaseWrapper,
					org.PublicId,
					InactiveState,
					TestConvertToUrls(t, tp.Addr())[0],
					"alice-rp", "alice-secret",
				).PublicId
			}(),
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "unable to transition from inactive",
		},
		{
			name:    "error-for-InActive-to-ActivePublic",
			toState: ActivePublicState,
			operateOn: func() string {
				org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
				databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
				require.NoError(t, err)
				// the returned oidc auth method is incomplete
				return TestAuthMethod(t,
					conn, databaseWrapper,
					org.PublicId,
					InactiveState,
					TestConvertToUrls(t, tp.Addr())[0],
					"alice-rp", "alice-secret",
				).PublicId
			}(),
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "unable to transition from inactive",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			var err error
			switch tt.toState {
			case InactiveState:
				err = repo.MakeInactive(ctx, tt.operateOn)
			case ActivePrivateState:
				err = repo.MakePrivate(ctx, tt.operateOn)
			case ActivePublicState:
				err = repo.MakePublic(ctx, tt.operateOn)
			default:
				require.Fail("unknown toState %s for test", tt.toState)
			}
			if tt.wantErrMatch != nil {
				require.Error(err)
				assert.Truef(errors.Match(tt.wantErrMatch, err), "want err code: %q got: %q", tt.wantErrMatch.Code, err)
				if tt.wantErrContains != "" {
					assert.Contains(err.Error(), tt.wantErrContains)
				}

				err := db.TestVerifyOplog(t, rw, tt.operateOn, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second))
				require.Errorf(err, "should not have found oplog entry for %s", tt.operateOn)
				return
			}
			require.NoError(err)
			found, err := repo.LookupAuthMethod(ctx, tt.operateOn)
			require.NoError(err)
			require.NotEmpty(found)
			assert.Equal(string(tt.toState), found.OperationalState)

			if !tt.wantNoOplog {
				err = db.TestVerifyOplog(t, rw, tt.operateOn, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second))
				require.NoErrorf(err, "unexpected error verifying oplog entry: %s", err)
			}
		})
	}

}
