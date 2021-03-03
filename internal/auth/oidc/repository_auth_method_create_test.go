package oidc

import (
	"context"
	"crypto/x509"
	"net/url"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestRepository_CreateAuthMethod(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	ctx := context.Background()
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))

	convertAlg := func(alg ...Alg) []string {
		s := make([]string, 0, len(alg))
		for _, a := range alg {
			s = append(s, string(a))
		}
		return s
	}
	convertUrls := func(cb ...*url.URL) []string {
		u := make([]string, 0, len(cb))
		for _, c := range cb {
			u = append(u, c.String())
		}
		return u
	}
	tests := []struct {
		name         string
		am           *AuthMethod
		opt          []Option
		wantErrMatch *errors.Template
	}{
		{
			name: "valid",
			am: func() *AuthMethod {
				algs := []Alg{RS256, ES256}
				cbs := TestConvertToUrls(t, "https://www.alice.com/callback")
				auds := []string{"alice-rp", "bob-rp"}
				cert1, pem1 := testGenerateCA(t, "localhost")
				cert2, pem2 := testGenerateCA(t, "localhost")
				certs := []*x509.Certificate{cert1, cert2}
				pems := []string{pem1, pem2}
				am, err := NewAuthMethod(
					org.PublicId,
					TestConvertToUrls(t, "https://www.alice.com")[0],
					"alice-rp",
					"alice-secret", WithAudClaims("alice-rp"),
					WithAudClaims(auds...),
					WithCallbackUrls(cbs...),
					WithSigningAlgs(algs...),
					WithCertificates(certs...),
					WithName("alice's restaurant"),
					WithDescription("it's a good place to eat"),
				)
				require.NoError(t, err)
				require.Equal(t, am.SigningAlgs, convertAlg(algs...))
				require.Equal(t, am.CallbackUrls, convertUrls(cbs...))
				require.Equal(t, am.AudClaims, auds)
				require.Equal(t, am.Certificates, pems)
				require.Equal(t, am.OperationalState, string(InactiveState))
				return am
			}(),
		},
		{
			name: "bad-public-id",
			am: func() *AuthMethod {
				id, err := newAuthMethodId()
				require.NoError(t, err)
				am := AllocAuthMethod()
				am.PublicId = id
				return &am
			}(),
			wantErrMatch: errors.T(errors.InvalidParameter),
		},
		{
			name: "bad-version",
			am: func() *AuthMethod {
				am := AllocAuthMethod()
				am.Version = 22
				return &am
			}(),
			wantErrMatch: errors.T(errors.InvalidParameter),
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

				err := db.TestVerifyOplog(t, rw, tt.am.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second))
				require.Errorf(err, "should not have found oplog entry for %s", tt.am.PublicId)
				return
			}
			require.NoError(err)
			tt.am.PublicId = got.PublicId
			tt.am.CreateTime = got.CreateTime
			tt.am.UpdateTime = got.UpdateTime
			tt.am.Version = got.Version
			assert.Truef(proto.Equal(tt.am.AuthMethod, got.AuthMethod), "got %+v expected %+v", got, tt.am)

			err = db.TestVerifyOplog(t, rw, tt.am.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second))
			require.NoErrorf(err, "unexpected error verifying oplog entry: %s", err)
		})
	}
}
