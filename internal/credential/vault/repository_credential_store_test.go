package vault

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/credential/vault/store"
	"github.com/hashicorp/boundary/internal/db"
	dbassert "github.com/hashicorp/boundary/internal/db/assert"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRepository_CreateCredentialStoreResource(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)

	t.Run("invalid-duplicate-names", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		ctx := context.Background()
		kms := kms.TestKms(t, conn, wrapper)
		repo, err := NewRepository(rw, rw, kms)
		require.NoError(err)
		require.NotNil(repo)
		_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))

		v, cleanup := NewTestVaultServer(t, TestNoTLS)
		defer cleanup()
		secret := v.CreateToken(t)
		token := secret.Auth.ClientToken

		in, err := NewCredentialStore(prj.GetPublicId(), v.Addr, []byte(token), WithName("gary"), WithDescription("46"))
		assert.NoError(err)
		require.NotNil(in)
		assert.NotEmpty(in.Name)
		got, err := repo.CreateCredentialStore(ctx, in)

		require.NoError(err)
		require.NotNil(got)
		assertPublicId(t, CredentialStorePrefix, got.PublicId)

		assert.NotSame(in, got)
		assert.Equal(in.Name, got.Name)
		assert.Equal(in.Description, got.Description)
		assert.Equal(got.CreateTime, got.UpdateTime)

		got2, err := repo.CreateCredentialStore(ctx, in)
		assert.Truef(errors.Match(errors.T(errors.NotUnique), err), "want err code: %v got err: %v", errors.NotUnique, err)
		assert.Nil(got2)
	})

	t.Run("valid-duplicate-names-diff-scopes", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		ctx := context.Background()
		kms := kms.TestKms(t, conn, wrapper)
		repo, err := NewRepository(rw, rw, kms)
		require.NoError(err)
		require.NotNil(repo)
		org, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))

		v, cleanup := NewTestVaultServer(t, TestNoTLS)
		defer cleanup()

		secret1 := v.CreateToken(t)
		token1 := secret1.Auth.ClientToken
		in1, err := NewCredentialStore(prj.GetPublicId(), v.Addr, []byte(token1), WithName("gary"), WithDescription("46"))
		assert.NoError(err)
		require.NotNil(in1)
		assert.NotEmpty(in1.Name)
		got1, err := repo.CreateCredentialStore(ctx, in1)
		require.NoError(err)
		require.NotNil(got1)
		assertPublicId(t, CredentialStorePrefix, got1.PublicId)
		assert.NotSame(in1, got1)
		assert.Equal(in1.Name, got1.Name)
		assert.Equal(in1.Description, got1.Description)
		assert.Equal(got1.CreateTime, got1.UpdateTime)

		secret2 := v.CreateToken(t)
		token2 := secret2.Auth.ClientToken
		in2, err := NewCredentialStore(org.GetPublicId(), v.Addr, []byte(token2), WithName("gary"), WithDescription("46"))
		assert.NoError(err)
		require.NotNil(in2)
		assert.NotEmpty(in2.Name)
		in2.ScopeId = org.GetPublicId()
		got2, err := repo.CreateCredentialStore(ctx, in2)
		require.NoError(err)
		require.NotNil(got2)
		assertPublicId(t, CredentialStorePrefix, got2.PublicId)
		assert.NotSame(in2, got2)
		assert.Equal(in2.Name, got2.Name)
		assert.Equal(in2.Description, got2.Description)
		assert.Equal(got2.CreateTime, got2.UpdateTime)

		assert.Equal(in1.Name, in2.Name)
		assert.Equal(got1.Name, got2.Name)
	})
}

func assertPublicId(t *testing.T, prefix, actual string) {
	t.Helper()
	assert.NotEmpty(t, actual)
	parts := strings.Split(actual, "_")
	assert.Equalf(t, 2, len(parts), "want one '_' in PublicId, got multiple in %q", actual)
	assert.Equalf(t, prefix, parts[0], "PublicId want prefix: %q, got: %q in %q", prefix, parts[0], actual)
}

func TestRepository_CreateCredentialStoreNonResource(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)

	tests := []struct {
		name      string
		tls       TestVaultTLS
		tokenOpts []TestOption
		wantIsErr errors.Code
	}{
		{
			name: "no-tls-valid-token",
		},
		{
			name: "server-tls-valid-token",
			tls:  TestServerTLS,
		},
		{
			name: "client-tls-valid-token",
			tls:  TestClientTLS,
		},
		{
			name:      "no-tls-token-not-renewable",
			tokenOpts: []TestOption{TestRenewableToken(t, false)},
			wantIsErr: errors.VaultTokenNotRenewable,
		},
		{
			name:      "no-tls-token-not-orphaned",
			tokenOpts: []TestOption{TestOrphanToken(t, false)},
			wantIsErr: errors.VaultTokenNotOrphaned,
		},
		{
			name:      "no-tls-token-not-periodic",
			tokenOpts: []TestOption{TestPeriodicToken(t, false)},
			wantIsErr: errors.VaultTokenNotPeriodic,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			ctx := context.Background()
			kms := kms.TestKms(t, conn, wrapper)
			repo, err := NewRepository(rw, rw, kms)
			require.NoError(err)
			require.NotNil(repo)
			_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))

			v, cleanup := NewTestVaultServer(t, tt.tls)
			defer cleanup()
			secret := v.CreateToken(t, tt.tokenOpts...)
			token := secret.Auth.ClientToken

			var opts []Option
			if tt.tls == TestServerTLS {
				opts = append(opts, WithCACert(v.CaCert))
			}
			if tt.tls == TestClientTLS {
				opts = append(opts, WithCACert(v.CaCert))
				clientCert, err := NewClientCertificate(v.ClientCert, v.ClientKey)
				require.NoError(err)
				opts = append(opts, WithClientCert(clientCert))
			}

			credStoreIn, err := NewCredentialStore(prj.GetPublicId(), v.Addr, []byte(token), opts...)
			assert.NoError(err)
			require.NotNil(credStoreIn)
			got, err := repo.CreateCredentialStore(ctx, credStoreIn)

			if tt.wantIsErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantIsErr), err), "want err: %q got: %q", tt.wantIsErr, err)
				assert.Nil(got)
				if got != nil {
					err := db.TestVerifyOplog(t, rw, got.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second))
					require.Errorf(err, "should not have found oplog entry for %s", got.PublicId)
				}
				return
			}
			require.NoError(err)
			assert.Empty(credStoreIn.PublicId)
			require.NotNil(got)
			assertPublicId(t, CredentialStorePrefix, got.PublicId)
			assert.NotSame(credStoreIn, got)
			assert.Equal(got.CreateTime, got.UpdateTime)
			assert.NoError(db.TestVerifyOplog(t, rw, got.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second)))

			outToken := allocToken()
			assert.NoError(rw.LookupWhere(ctx, &outToken, "store_id = ?", got.PublicId))

			if tt.tls == TestClientTLS {
				outClientCert := allocClientCertificate()
				assert.NoError(rw.LookupWhere(ctx, &outClientCert, "store_id = ?", got.PublicId))
			}
		})
	}
}

func TestRepository_LookupCredentialStore(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)

	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	stores := TestCredentialStores(t, conn, wrapper, prj.PublicId, 2)
	csWithClientCert := stores[0]
	csWithoutClientCert := stores[1]

	ccert := allocClientCertificate()
	rows, err := rw.Delete(context.Background(), ccert, db.WithWhere("store_id = ?", csWithoutClientCert.GetPublicId()))
	require.NoError(t, err)
	require.Equal(t, 1, rows)

	badId, err := newCredentialStoreId()
	assert.NoError(t, err)
	require.NotNil(t, badId)

	// TODO(mgaffney) 04/2021: Add test for credential stores with no
	// 'current' token
	tests := []struct {
		name           string
		id             string
		want           *CredentialStore
		wantClientCert bool
		wantErr        errors.Code
	}{
		{
			name:           "valid-with-client-cert",
			id:             csWithClientCert.GetPublicId(),
			want:           csWithClientCert,
			wantClientCert: true,
		},
		{
			name:           "valid-without-client-cert",
			id:             csWithoutClientCert.GetPublicId(),
			want:           csWithoutClientCert,
			wantClientCert: false,
		},
		{
			name:    "empty-public-id",
			id:      "",
			wantErr: errors.InvalidParameter,
		},
		{
			name: "not-found",
			id:   badId,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			ctx := context.Background()
			kms := kms.TestKms(t, conn, wrapper)
			repo, err := NewRepository(rw, rw, kms)
			assert.NoError(err)
			require.NotNil(repo)

			got, err := repo.LookupCredentialStore(ctx, tt.id)
			if tt.wantErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantErr), err), "want err: %q got: %q", tt.wantErr, err)
				assert.Nil(got)
				return
			}
			require.NoError(err)

			if tt.want == nil {
				assert.Nil(got)
				return
			}

			assert.NotNil(got)
			assert.NotSame(got, tt.want)
			assert.NotNil(got.Token(), "token")

			if tt.wantClientCert {
				assert.NotNil(got.ClientCertificate(), "client certificate")
			} else {
				assert.Nil(got.ClientCertificate(), "client certificate")
			}
		})
	}
}

func TestRepository_lookupPrivateCredentialStore(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)

	tests := []struct {
		name    string
		tls     TestVaultTLS
		wantErr errors.Code
	}{
		{
			name: "no-tls-valid-token",
		},
		{
			name: "server-tls-valid-token",
			tls:  TestServerTLS,
		},
		{
			name: "client-tls-valid-token",
			tls:  TestClientTLS,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			ctx := context.Background()
			kms := kms.TestKms(t, conn, wrapper)
			repo, err := NewRepository(rw, rw, kms)
			require.NoError(err)
			require.NotNil(repo)
			_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))

			v, cleanup := NewTestVaultServer(t, tt.tls)
			defer cleanup()

			var opts []Option
			if tt.tls == TestServerTLS {
				opts = append(opts, WithCACert(v.CaCert))
			}
			if tt.tls == TestClientTLS {
				opts = append(opts, WithCACert(v.CaCert))
				clientCert, err := NewClientCertificate(v.ClientCert, v.ClientKey)
				require.NoError(err)
				opts = append(opts, WithClientCert(clientCert))
			}

			secret := v.CreateToken(t)
			token := secret.Auth.ClientToken

			credStoreIn, err := NewCredentialStore(prj.GetPublicId(), v.Addr, []byte(token), opts...)
			assert.NoError(err)
			require.NotNil(credStoreIn)
			orig, err := repo.CreateCredentialStore(ctx, credStoreIn)
			assert.NoError(err)
			require.NotNil(orig)

			origLookup, err := repo.LookupCredentialStore(ctx, orig.GetPublicId())
			assert.NoError(err)
			require.NotNil(origLookup)
			assert.NotNil(origLookup.Token())
			assert.Equal(orig.GetPublicId(), origLookup.GetPublicId())

			got, err := repo.lookupPrivateCredentialStore(ctx, orig.GetPublicId())
			if tt.wantErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantErr), err), "want err: %q got: %q", tt.wantErr, err)
				assert.Nil(got)
				return
			}
			assert.NoError(err)
			require.NotNil(got)
			assert.Equal(orig.GetPublicId(), got.GetPublicId())

			assert.Nil(got.outputToken)
			require.NotNil(got.privateToken)
			assert.Equal([]byte(token), got.privateToken.GetToken())

			if tt.tls == TestClientTLS {
				assert.Nil(got.clientCert)
				require.NotNil(got.privateClientCert)
				assert.Equal(v.ClientKey, got.privateClientCert.CertificateKey)
			}
		})
	}
}

func TestRepository_UpdateCredentialStore_Attributes(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)

	// TODO(mgaffney) 04/2021:
	// Add tests for changing and deleting :
	// - [ ] vault address
	// - [ ] vault token
	// - [x] ca certificate
	// - [ ] client certificate
	// - [x] namespace
	// - [x] tls skip verify
	// - [x] tls server name

	changeNamespace := func(n string) func(*CredentialStore) *CredentialStore {
		return func(cs *CredentialStore) *CredentialStore {
			cs.Namespace = n
			return cs
		}
	}

	changeTlsServerName := func(n string) func(*CredentialStore) *CredentialStore {
		return func(cs *CredentialStore) *CredentialStore {
			cs.TlsServerName = n
			return cs
		}
	}

	changeTlsSkipVerify := func(t bool) func(*CredentialStore) *CredentialStore {
		return func(cs *CredentialStore) *CredentialStore {
			cs.TlsSkipVerify = t
			return cs
		}
	}

	changeName := func(n string) func(*CredentialStore) *CredentialStore {
		return func(cs *CredentialStore) *CredentialStore {
			cs.Name = n
			return cs
		}
	}

	changeDescription := func(d string) func(*CredentialStore) *CredentialStore {
		return func(cs *CredentialStore) *CredentialStore {
			cs.Description = d
			return cs
		}
	}

	makeNil := func() func(*CredentialStore) *CredentialStore {
		return func(cs *CredentialStore) *CredentialStore {
			return nil
		}
	}

	makeEmbeddedNil := func() func(*CredentialStore) *CredentialStore {
		return func(cs *CredentialStore) *CredentialStore {
			return &CredentialStore{}
		}
	}

	deletePublicId := func() func(*CredentialStore) *CredentialStore {
		return func(cs *CredentialStore) *CredentialStore {
			cs.PublicId = ""
			return cs
		}
	}

	nonExistentPublicId := func() func(*CredentialStore) *CredentialStore {
		return func(cs *CredentialStore) *CredentialStore {
			cs.PublicId = "abcd_OOOOOOOOOO"
			return cs
		}
	}

	combine := func(fns ...func(cs *CredentialStore) *CredentialStore) func(*CredentialStore) *CredentialStore {
		return func(cs *CredentialStore) *CredentialStore {
			for _, fn := range fns {
				cs = fn(cs)
			}
			return cs
		}
	}

	tests := []struct {
		name      string
		orig      *CredentialStore
		chgFn     func(*CredentialStore) *CredentialStore
		masks     []string
		want      *CredentialStore
		wantCount int
		wantIsErr errors.Code
	}{
		{
			name: "nil-credential-store",
			orig: &CredentialStore{
				CredentialStore: &store.CredentialStore{},
			},
			chgFn:     makeNil(),
			masks:     []string{"Name", "Description"},
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "nil-embedded-credential-store",
			orig: &CredentialStore{
				CredentialStore: &store.CredentialStore{},
			},
			chgFn:     makeEmbeddedNil(),
			masks:     []string{"Name", "Description"},
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "no-public-id",
			orig: &CredentialStore{
				CredentialStore: &store.CredentialStore{},
			},
			chgFn:     deletePublicId(),
			masks:     []string{"Name", "Description"},
			wantIsErr: errors.InvalidPublicId,
		},
		{
			name: "updating-non-existent-credential-store",
			orig: &CredentialStore{
				CredentialStore: &store.CredentialStore{
					Name: "test-name-repo",
				},
			},
			chgFn:     combine(nonExistentPublicId(), changeName("test-update-name-repo")),
			masks:     []string{"Name"},
			wantIsErr: errors.RecordNotFound,
		},
		{
			name: "empty-field-mask",
			orig: &CredentialStore{
				CredentialStore: &store.CredentialStore{
					Name: "test-name-repo",
				},
			},
			chgFn:     changeName("test-update-name-repo"),
			wantIsErr: errors.EmptyFieldMask,
		},
		{
			name: "read-only-fields-in-field-mask",
			orig: &CredentialStore{
				CredentialStore: &store.CredentialStore{
					Name: "test-name-repo",
				},
			},
			chgFn:     changeName("test-update-name-repo"),
			masks:     []string{"PublicId", "CreateTime", "UpdateTime", "ScopeId"},
			wantIsErr: errors.InvalidFieldMask,
		},
		{
			name: "unknown-field-in-field-mask",
			orig: &CredentialStore{
				CredentialStore: &store.CredentialStore{
					Name: "test-name-repo",
				},
			},
			chgFn:     changeName("test-update-name-repo"),
			masks:     []string{"Bilbo"},
			wantIsErr: errors.InvalidFieldMask,
		},
		{
			name: "change-name",
			orig: &CredentialStore{
				CredentialStore: &store.CredentialStore{
					Name: "test-name-repo",
				},
			},
			chgFn: changeName("test-update-name-repo"),
			masks: []string{"Name"},
			want: &CredentialStore{
				CredentialStore: &store.CredentialStore{
					Name: "test-update-name-repo",
				},
			},
			wantCount: 1,
		},
		{
			name: "change-description",
			orig: &CredentialStore{
				CredentialStore: &store.CredentialStore{
					Description: "test-description-repo",
				},
			},
			chgFn: changeDescription("test-update-description-repo"),
			masks: []string{"Description"},
			want: &CredentialStore{
				CredentialStore: &store.CredentialStore{
					Description: "test-update-description-repo",
				},
			},
			wantCount: 1,
		},
		{
			name: "change-name-and-description",
			orig: &CredentialStore{
				CredentialStore: &store.CredentialStore{
					Name:        "test-name-repo",
					Description: "test-description-repo",
				},
			},
			chgFn: combine(changeDescription("test-update-description-repo"), changeName("test-update-name-repo")),
			masks: []string{"Name", "Description"},
			want: &CredentialStore{
				CredentialStore: &store.CredentialStore{
					Name:        "test-update-name-repo",
					Description: "test-update-description-repo",
				},
			},
			wantCount: 1,
		},
		{
			name: "delete-name",
			orig: &CredentialStore{
				CredentialStore: &store.CredentialStore{
					Name:        "test-name-repo",
					Description: "test-description-repo",
				},
			},
			masks: []string{"Name"},
			chgFn: combine(changeDescription("test-update-description-repo"), changeName("")),
			want: &CredentialStore{
				CredentialStore: &store.CredentialStore{
					Description: "test-description-repo",
				},
			},
			wantCount: 1,
		},
		{
			name: "delete-description",
			orig: &CredentialStore{
				CredentialStore: &store.CredentialStore{
					Name:        "test-name-repo",
					Description: "test-description-repo",
				},
			},
			masks: []string{"Description"},
			chgFn: combine(changeDescription(""), changeName("test-update-name-repo")),
			want: &CredentialStore{
				CredentialStore: &store.CredentialStore{
					Name: "test-name-repo",
				},
			},
			wantCount: 1,
		},
		{
			name: "do-not-delete-name",
			orig: &CredentialStore{
				CredentialStore: &store.CredentialStore{
					Name:        "test-name-repo",
					Description: "test-description-repo",
				},
			},
			masks: []string{"Description"},
			chgFn: combine(changeDescription("test-update-description-repo"), changeName("")),
			want: &CredentialStore{
				CredentialStore: &store.CredentialStore{
					Name:        "test-name-repo",
					Description: "test-update-description-repo",
				},
			},
			wantCount: 1,
		},
		{
			name: "do-not-delete-description",
			orig: &CredentialStore{
				CredentialStore: &store.CredentialStore{
					Name:        "test-name-repo",
					Description: "test-description-repo",
				},
			},
			masks: []string{"Name"},
			chgFn: combine(changeDescription(""), changeName("test-update-name-repo")),
			want: &CredentialStore{
				CredentialStore: &store.CredentialStore{
					Name:        "test-update-name-repo",
					Description: "test-description-repo",
				},
			},
			wantCount: 1,
		},
		{
			name: "change-namespace",
			orig: &CredentialStore{
				CredentialStore: &store.CredentialStore{
					Namespace: "test-namespace",
				},
			},
			chgFn: changeNamespace("test-update-namespace"),
			masks: []string{"namespace"},
			want: &CredentialStore{
				CredentialStore: &store.CredentialStore{
					Namespace: "test-update-namespace",
				},
			},
			wantCount: 1,
		},
		{
			name: "delete-namespace",
			orig: &CredentialStore{
				CredentialStore: &store.CredentialStore{
					Namespace: "test-namespace",
				},
			},
			chgFn: changeNamespace(""),
			masks: []string{"namespace"},
			want: &CredentialStore{
				CredentialStore: &store.CredentialStore{},
			},
			wantCount: 1,
		},
		{
			name: "change-tls-server-name",
			orig: &CredentialStore{
				CredentialStore: &store.CredentialStore{
					TlsServerName: "tls-server-name",
				},
			},
			chgFn: changeTlsServerName("tls-server-name-update"),
			masks: []string{"TlsServerName"},
			want: &CredentialStore{
				CredentialStore: &store.CredentialStore{
					TlsServerName: "tls-server-name-update",
				},
			},
			wantCount: 1,
		},
		{
			name: "delete-tls-server-name",
			orig: &CredentialStore{
				CredentialStore: &store.CredentialStore{
					TlsServerName: "tls-server-name",
				},
			},
			chgFn: changeTlsServerName(""),
			masks: []string{"TlsServerName"},
			want: &CredentialStore{
				CredentialStore: &store.CredentialStore{},
			},
			wantCount: 1,
		},
		{
			name: "tls-skip-verify-false2true",
			orig: &CredentialStore{
				CredentialStore: &store.CredentialStore{
					TlsSkipVerify: false,
				},
			},
			chgFn: changeTlsSkipVerify(true),
			masks: []string{"TlsSkipVerify"},
			want: &CredentialStore{
				CredentialStore: &store.CredentialStore{
					TlsSkipVerify: true,
				},
			},
			wantCount: 1,
		},
		{
			name: "tls-skip-verify-true2false",
			orig: &CredentialStore{
				CredentialStore: &store.CredentialStore{
					TlsSkipVerify: true,
				},
			},
			chgFn: changeTlsSkipVerify(false),
			masks: []string{"TlsSkipVerify"},
			want: &CredentialStore{
				CredentialStore: &store.CredentialStore{
					TlsSkipVerify: false,
				},
			},
			wantCount: 1,
		},
		{
			name: "tls-skip-verify-false2false",
			orig: &CredentialStore{
				CredentialStore: &store.CredentialStore{
					TlsSkipVerify: false,
				},
			},
			chgFn: changeTlsSkipVerify(false),
			masks: []string{"TlsSkipVerify"},
			want: &CredentialStore{
				CredentialStore: &store.CredentialStore{
					TlsSkipVerify: false,
				},
			},
			wantCount: 1,
		},
		{
			name: "tls-skip-verify-true2true",
			orig: &CredentialStore{
				CredentialStore: &store.CredentialStore{
					TlsSkipVerify: true,
				},
			},
			chgFn: changeTlsSkipVerify(true),
			masks: []string{"TlsSkipVerify"},
			want: &CredentialStore{
				CredentialStore: &store.CredentialStore{
					TlsSkipVerify: true,
				},
			},
			wantCount: 1,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			ctx := context.Background()
			kms := kms.TestKms(t, conn, wrapper)
			repo, err := NewRepository(rw, rw, kms)
			assert.NoError(err)
			require.NotNil(repo)

			_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
			tt.orig.ScopeId = prj.GetPublicId()

			vs, cleanup := NewTestVaultServer(t, TestNoTLS)
			defer cleanup()

			tt.orig.VaultAddress = vs.Addr

			secret := vs.CreateToken(t)
			token, err := secret.TokenID()
			require.NoError(err)
			require.NotEmpty(token)
			tt.orig.inputToken = []byte(token)

			orig, err := repo.CreateCredentialStore(ctx, tt.orig)
			assert.NoError(err)
			require.NotNil(orig)

			if tt.chgFn != nil {
				orig = tt.chgFn(orig)
			}
			got, gotCount, err := repo.UpdateCredentialStore(ctx, orig, 1, tt.masks)
			if tt.wantIsErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantIsErr), err), "want err: %q got: %q", tt.wantIsErr, err)
				assert.Equal(tt.wantCount, gotCount, "row count")
				assert.Nil(got)
				return
			}
			assert.NoError(err)
			assert.Empty(tt.orig.PublicId)
			require.NotNil(got)
			assertPublicId(t, CredentialStorePrefix, got.PublicId)
			assert.Equal(tt.wantCount, gotCount, "row count")
			assert.NotSame(tt.orig, got)
			assert.Equal(tt.orig.ScopeId, got.ScopeId)
			dbassert := dbassert.New(t, conn.DB())
			if tt.want.Name == "" {
				dbassert.IsNull(got, "name")
			} else {
				assert.Equal(tt.want.Name, got.Name)
			}

			if tt.want.Description == "" {
				dbassert.IsNull(got, "description")
			} else {
				assert.Equal(tt.want.Description, got.Description)
			}

			if tt.want.Namespace == "" {
				dbassert.IsNull(got, "namespace")
			} else {
				assert.Equal(tt.want.Namespace, got.Namespace)
			}

			if tt.want.TlsServerName == "" {
				dbassert.IsNull(got, "TlsServerName")
			} else {
				assert.Equal(tt.want.TlsServerName, got.TlsServerName)
			}

			assert.Equal(tt.want.TlsSkipVerify, got.TlsSkipVerify)

			if tt.wantCount > 0 {
				assert.NoError(db.TestVerifyOplog(t, rw, got.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second)))
			}
		})
	}

	t.Run("change-ca-cert", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		ctx := context.Background()
		kms := kms.TestKms(t, conn, wrapper)
		repo, err := NewRepository(rw, rw, kms)
		assert.NoError(err)
		require.NotNil(repo)

		vs, cleanup := NewTestVaultServer(t, TestServerTLS)
		defer cleanup()

		secret := vs.CreateToken(t)
		token, err := secret.TokenID()
		require.NoError(err)
		require.NotEmpty(token)

		_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		in := &CredentialStore{
			inputToken: []byte(token),
			CredentialStore: &store.CredentialStore{
				ScopeId:      prj.GetPublicId(),
				VaultAddress: vs.Addr,
				CaCert:       vs.CaCert,
			},
		}

		orig, err := repo.CreateCredentialStore(ctx, in)
		assert.NoError(err)
		require.NotNil(orig)
		assert.Equal(vs.CaCert, orig.CaCert)

		// Change CA Cert
		orig.CaCert = vs.ServerCert
		got1, gotCount1, err := repo.UpdateCredentialStore(ctx, orig, 1, []string{"cacert"})
		assert.NoError(err)
		assert.Equal(1, gotCount1, "count of updated records")
		require.NotNil(got1)
		assert.Equal(vs.ServerCert, got1.CaCert)

		// Delete CA Cert
		orig.CaCert = nil
		got2, gotCount2, err := repo.UpdateCredentialStore(ctx, orig, 2, []string{"cacert"})
		assert.NoError(err)
		assert.Equal(1, gotCount2, "count of updated records")
		require.NotNil(got2)
		assert.Nil(got2.CaCert)

		dbassert := dbassert.New(t, conn.DB())
		dbassert.IsNull(got2, "CaCert")
	})

	t.Run("invalid-duplicate-names", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		ctx := context.Background()
		kms := kms.TestKms(t, conn, wrapper)
		repo, err := NewRepository(rw, rw, kms)
		assert.NoError(err)
		require.NotNil(repo)

		name := "test-dup-name"
		_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		css := TestCredentialStores(t, conn, wrapper, prj.PublicId, 2)

		csA, csB := css[0], css[1]

		csA.Name = name
		got1, gotCount1, err := repo.UpdateCredentialStore(ctx, csA, 1, []string{"name"})
		assert.NoError(err)
		require.NotNil(got1)
		assert.Equal(name, got1.Name)
		assert.Equal(1, gotCount1, "row count")
		assert.NoError(db.TestVerifyOplog(t, rw, csA.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second)))

		csB.Name = name
		got2, gotCount2, err := repo.UpdateCredentialStore(ctx, csB, 1, []string{"name"})
		assert.Truef(errors.Match(errors.T(errors.NotUnique), err), "want err code: %v got err: %v", errors.NotUnique, err)
		assert.Nil(got2)
		assert.Equal(db.NoRowsAffected, gotCount2, "row count")
	})

	t.Run("valid-duplicate-names-diff-scopes", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		ctx := context.Background()
		kms := kms.TestKms(t, conn, wrapper)
		repo, err := NewRepository(rw, rw, kms)
		assert.NoError(err)
		require.NotNil(repo)

		vs, cleanup := NewTestVaultServer(t, TestNoTLS)
		defer cleanup()

		token1, err := vs.CreateToken(t).TokenID()
		require.NoError(err)
		require.NotEmpty(token1)

		token2, err := vs.CreateToken(t).TokenID()
		require.NoError(err)
		require.NotEmpty(token2)

		org, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		in := &CredentialStore{
			inputToken: []byte(token1),
			CredentialStore: &store.CredentialStore{
				Name:         "test-name-repo",
				VaultAddress: vs.Addr,
			},
		}
		in2 := in.clone()
		in2.inputToken = []byte(token2)

		in.ScopeId = prj.GetPublicId()
		got, err := repo.CreateCredentialStore(ctx, in)
		assert.NoError(err)
		require.NotNil(got)
		assertPublicId(t, CredentialStorePrefix, got.PublicId)
		assert.NotSame(in, got)
		assert.Equal(in.Name, got.Name)
		assert.Equal(in.Description, got.Description)

		in2.ScopeId = org.GetPublicId()
		in2.Name = "first-name"
		got2, err := repo.CreateCredentialStore(ctx, in2)
		assert.NoError(err)
		require.NotNil(got2)
		got2.Name = got.Name
		got3, gotCount3, err := repo.UpdateCredentialStore(ctx, got2, 1, []string{"name"})
		assert.NoError(err)
		require.NotNil(got3)
		assert.NotSame(got2, got3)
		assert.Equal(got.Name, got3.Name)
		assert.Equal(got2.Description, got3.Description)
		assert.Equal(1, gotCount3, "row count")
	})

	t.Run("change-scope-id", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		ctx := context.Background()
		kms := kms.TestKms(t, conn, wrapper)
		repo, err := NewRepository(rw, rw, kms)
		assert.NoError(err)
		require.NotNil(repo)

		iamRepo := iam.TestRepo(t, conn, wrapper)
		_, prj1 := iam.TestScopes(t, iamRepo)
		_, prj2 := iam.TestScopes(t, iamRepo)
		csA, csB := TestCredentialStores(t, conn, wrapper, prj1.PublicId, 1)[0], TestCredentialStores(t, conn, wrapper, prj2.PublicId, 1)[0]
		assert.NotEqual(csA.ScopeId, csB.ScopeId)
		orig := csA.clone()

		csA.ScopeId = csB.ScopeId
		assert.Equal(csA.ScopeId, csB.ScopeId)

		got1, gotCount1, err := repo.UpdateCredentialStore(ctx, csA, 1, []string{"name"})

		assert.NoError(err)
		require.NotNil(got1)
		assert.Equal(orig.ScopeId, got1.ScopeId)
		assert.Equal(1, gotCount1, "row count")
	})
}
