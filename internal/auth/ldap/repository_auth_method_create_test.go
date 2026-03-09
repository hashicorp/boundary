// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package ldap

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestRepository_CreateAuthMethod(t *testing.T) {
	testConn, _ := db.TestSetup(t, "postgres")
	testRw := db.New(testConn)
	testWrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, testConn, testWrapper)
	testCtx := context.Background()
	org, _ := iam.TestScopes(t, iam.TestRepo(t, testConn, testWrapper))
	testCert, _ := TestGenerateCA(t, "localhost")
	testCert2, _ := TestGenerateCA(t, "localhost")
	_, testPrivKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	derPrivKey, err := x509.MarshalPKCS8PrivateKey(testPrivKey)
	require.NoError(t, err)

	testAm, err := NewAuthMethod(
		testCtx,
		org.PublicId,
		WithUrls(testCtx, TestConvertToUrls(t, "ldaps://ldap1", "ldap://ldap2")...),
		WithName(testCtx, "test-name"),
		WithDescription(testCtx, "test-description"),
		WithStartTLS(testCtx),
		WithInsecureTLS(testCtx),
		WithDiscoverDn(testCtx),
		WithAnonGroupSearch(testCtx),
		WithUpnDomain(testCtx, "alice.com"),
		WithUserDn(testCtx, "user-dn"),
		WithUserAttr(testCtx, "user-attr"),
		WithUserFilter(testCtx, "user-filter"),
		WithEnableGroups(testCtx),
		WithUseTokenGroups(testCtx),
		WithGroupDn(testCtx, "group-dn"),
		WithGroupAttr(testCtx, "group-attr"),
		WithGroupFilter(testCtx, "group-filter"),
		WithBindCredential(testCtx, "bind-dn", "bind-password"),
		WithCertificates(testCtx, testCert, testCert2),
		WithClientCertificate(testCtx, derPrivKey, testCert), // not a client cert but good enough for this test.
		WithAccountAttributeMap(testCtx, map[string]AccountToAttribute{
			"mail": ToEmailAttribute,
		}),
		WithDerefAliases(testCtx, DerefFindingBaseObj),
		WithMaximumPageSize(testCtx, 10),
	)
	require.NoError(t, err)

	tests := []struct {
		name            string
		kms             kms.GetWrapperer
		setup           func(*testing.T) *AuthMethod
		opt             []Option
		wantErrMatch    *errors.Template
		wantErrContains string
	}{
		{
			name: "valid",
			kms:  testKms,
			setup: func(t *testing.T) *AuthMethod {
				return testAm.clone()
			},
		},
		{
			name: "bind-cred-encrypt-err",
			kms: &mockGetWrapperer{
				returnDbWrapper: &kms.MockWrapper{
					EncryptErr: errors.New(testCtx, errors.Encrypt, "test", "bind-cred-encrypt-err"),
				},
			},
			setup: func(t *testing.T) *AuthMethod {
				return testAm.clone()
			},
			wantErrMatch:    errors.T(errors.Unknown),
			wantErrContains: "bind-cred-encrypt-err",
		},
		{
			name: "get-db-wrapper-err",
			kms: &mockGetWrapperer{
				getErr: errors.New(testCtx, errors.Encrypt, "test", "get-db-wrapper-err"),
			},
			setup: func(t *testing.T) *AuthMethod {
				return testAm.clone()
			},
			wantErrMatch:    errors.T(errors.Encrypt),
			wantErrContains: "unable to get database wrapper",
		},
		{
			name: "get-oplog-wrapper-err",
			kms: &mockGetWrapperer{
				getErr:          errors.New(testCtx, errors.Encrypt, "test", "get-db-wrapper-err"),
				returnDbWrapper: testWrapper,
			},
			setup: func(t *testing.T) *AuthMethod {
				return testAm.clone()
			},
			wantErrMatch:    errors.T(errors.Encrypt),
			wantErrContains: "unable to get oplog wrapper",
		},
		{
			name: "bad-state",
			kms:  testKms,
			setup: func(t *testing.T) *AuthMethod {
				am, err := NewAuthMethod(testCtx, org.PublicId, WithUrls(testCtx, TestConvertToUrls(t, "ldaps://ldap1")...))
				require.NoError(t, err)
				am.OperationalState = "not-a-valid-state"
				return am
			},
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "invalid state",
		},
		{
			name: "missing-auth-method",
			kms:  testKms,
			setup: func(t *testing.T) *AuthMethod {
				return nil
			},
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing auth method",
		},
		{
			name: "missing-scope",
			kms:  testKms,
			setup: func(t *testing.T) *AuthMethod {
				am, err := NewAuthMethod(testCtx, org.PublicId, WithUrls(testCtx, TestConvertToUrls(t, "ldaps://ldap1")...))
				require.NoError(t, err)
				am.ScopeId = ""
				return am
			},
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing scope id",
		},
		{
			name: "convert-err",
			kms:  testKms,
			setup: func(t *testing.T) *AuthMethod {
				am, err := NewAuthMethod(testCtx, org.PublicId, WithUrls(testCtx, TestConvertToUrls(t, "ldaps://ldap1")...))
				require.NoError(t, err)
				am.BindDn = "bind-dn"
				return am
			},
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing password",
		},
		{
			name: "missing-urls",
			kms:  testKms,
			setup: func(t *testing.T) *AuthMethod {
				am, err := NewAuthMethod(testCtx, org.PublicId, WithUrls(testCtx, TestConvertToUrls(t, "ldaps://ldap1")...))
				require.NoError(t, err)
				am.Urls = nil
				return am
			},
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing urls (there must be at least one)",
		},
		{
			name: "bad-public-id",
			kms:  testKms,
			setup: func(t *testing.T) *AuthMethod {
				id, err := newAuthMethodId(testCtx)
				require.NoError(t, err)
				am := AllocAuthMethod()
				am.PublicId = id
				return &am
			},
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "public id must be empty",
		},
		{
			name: "bad-version",
			kms:  testKms,
			setup: func(t *testing.T) *AuthMethod {
				am := AllocAuthMethod()
				am.Version = 22
				return &am
			},
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "version must be empty",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(testCtx, testRw, testRw, tc.kms)
			assert.NoError(err)
			require.NotNil(repo)
			am := tc.setup(t)
			got, err := repo.CreateAuthMethod(testCtx, am, tc.opt...)
			if tc.wantErrMatch != nil {
				require.Error(err)
				assert.Truef(errors.Match(tc.wantErrMatch, err), "want err code: %q got: %q", tc.wantErrMatch, err)
				assert.Nil(got)

				if am != nil {
					err := db.TestVerifyOplog(t, testRw, am.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second))
					require.Errorf(err, "should not have found oplog entry for %s", am.PublicId)
				}

				if tc.wantErrContains != "" {
					assert.Contains(err.Error(), tc.wantErrContains)
				}
				return
			}
			require.NoError(err)
			am.PublicId = got.PublicId
			am.CreateTime = got.CreateTime
			am.UpdateTime = got.UpdateTime
			am.Version = got.Version
			am.BindPasswordHmac = got.BindPasswordHmac
			am.ClientCertificateKeyHmac = got.ClientCertificateKeyHmac
			TestSortAuthMethods(t, []*AuthMethod{am, got})
			assert.Truef(proto.Equal(am.AuthMethod, got.AuthMethod), "got %+v expected %+v", got.AuthMethod, am.AuthMethod)

			err = db.TestVerifyOplog(t, testRw, am.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second))
			require.NoErrorf(err, "unexpected error verifying oplog entry: %s", err)

			found, err := repo.LookupAuthMethod(testCtx, am.PublicId)
			require.NoError(err)
			found.CreateTime = got.CreateTime
			found.UpdateTime = got.UpdateTime
			found.Version = got.Version
			TestSortAuthMethods(t, []*AuthMethod{found, am})
			assert.Empty(cmp.Diff(found.AuthMethod, am.AuthMethod, protocmp.Transform()))
		})
	}
}

type mockGetWrapperer struct {
	// kms is the underlying kms which is used to provide the mock's default
	// behavior
	kms kms.GetWrapperer

	// getErr is a mock value to return for the GetWrapper(...) operation
	getErr error

	returnOplogWrapper wrapping.Wrapper
	returnDbWrapper    wrapping.Wrapper
}

func (m *mockGetWrapperer) GetWrapper(ctx context.Context, scopeId string, purpose kms.KeyPurpose, opt ...kms.Option) (wrapping.Wrapper, error) {
	switch {
	case purpose == kms.KeyPurposeOplog && m.returnOplogWrapper != nil:
		return m.returnOplogWrapper, nil
	case purpose == kms.KeyPurposeDatabase && m.returnDbWrapper != nil:
		return m.returnDbWrapper, nil
	case m.getErr != nil:
		return nil, m.getErr
	default:
		return m.kms.GetWrapper(ctx, scopeId, purpose, opt...)
	}
}
