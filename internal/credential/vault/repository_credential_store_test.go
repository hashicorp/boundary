// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/credential/vault/store"
	"github.com/hashicorp/boundary/internal/db"
	dbassert "github.com/hashicorp/boundary/internal/db/assert"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/scheduler"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestRepository_CreateCredentialStoreResource(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	sche := scheduler.TestScheduler(t, conn, wrapper)

	t.Run("invalid-duplicate-names", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		ctx := context.Background()
		kms := kms.TestKms(t, conn, wrapper)
		repo, err := NewRepository(ctx, rw, rw, kms, sche)
		require.NoError(err)
		require.NotNil(repo)
		_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		err = RegisterJobs(ctx, sche, rw, rw, kms)
		require.NoError(err)

		v := NewTestVaultServer(t)
		_, token := v.CreateToken(t)

		in, err := NewCredentialStore(prj.GetPublicId(), v.Addr, []byte(token), WithName("gary"), WithDescription("46"))
		assert.NoError(err)
		require.NotNil(in)
		assert.NotEmpty(in.Name)
		got, err := repo.CreateCredentialStore(ctx, in)

		require.NoError(err)
		require.NotNil(got)
		assertPublicId(t, globals.VaultCredentialStorePrefix, got.PublicId)

		assert.NotSame(in, got)
		assert.Equal(in.Name, got.Name)
		assert.Equal(in.Description, got.Description)
		assert.Equal(got.CreateTime, got.UpdateTime)

		got2, err := repo.CreateCredentialStore(ctx, in)
		assert.Truef(errors.Match(errors.T(errors.NotUnique), err), "want err code: %v got err: %v", errors.NotUnique, err)
		assert.Nil(got2)
	})

	t.Run("valid-duplicate-names-diff-projects", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		ctx := context.Background()
		kms := kms.TestKms(t, conn, wrapper)
		repo, err := NewRepository(ctx, rw, rw, kms, sche)
		require.NoError(err)
		require.NotNil(repo)
		org, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		prj2 := iam.TestProject(t, iam.TestRepo(t, conn, wrapper), org.GetPublicId())
		err = RegisterJobs(ctx, sche, rw, rw, kms)
		require.NoError(err)

		v := NewTestVaultServer(t)

		_, token1 := v.CreateToken(t)
		in1, err := NewCredentialStore(prj.GetPublicId(), v.Addr, []byte(token1), WithName("gary"), WithDescription("46"))
		assert.NoError(err)
		require.NotNil(in1)
		assert.NotEmpty(in1.Name)
		got1, err := repo.CreateCredentialStore(ctx, in1)
		require.NoError(err)
		require.NotNil(got1)
		assertPublicId(t, globals.VaultCredentialStorePrefix, got1.PublicId)
		assert.NotSame(in1, got1)
		assert.Equal(in1.Name, got1.Name)
		assert.Equal(in1.Description, got1.Description)
		assert.Equal(got1.CreateTime, got1.UpdateTime)

		_, token2 := v.CreateToken(t)
		in2, err := NewCredentialStore(prj2.GetPublicId(), v.Addr, []byte(token2), WithName("gary"), WithDescription("46"))
		assert.NoError(err)
		require.NotNil(in2)
		assert.NotEmpty(in2.Name)
		in2.ProjectId = prj2.GetPublicId()
		got2, err := repo.CreateCredentialStore(ctx, in2)
		require.NoError(err)
		require.NotNil(got2)
		assertPublicId(t, globals.VaultCredentialStorePrefix, got2.PublicId)
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
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	sche := scheduler.TestScheduler(t, conn, wrapper)

	tests := []struct {
		name      string
		tls       TestVaultTLS
		tokenOpts []TestOption
		wantErr   errors.Code
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
			name:      "token-missing-capabilities",
			tokenOpts: []TestOption{WithPolicies([]string{"default"})},
			wantErr:   errors.VaultTokenMissingCapabilities,
		},
		{
			name:      "no-tls-token-not-renewable",
			tokenOpts: []TestOption{TestRenewableToken(false)},
			wantErr:   errors.VaultTokenNotRenewable,
		},
		{
			name:      "no-tls-token-not-orphan",
			tokenOpts: []TestOption{TestOrphanToken(false)},
			wantErr:   errors.VaultTokenNotOrphan,
		},
		{
			name:      "no-tls-token-not-periodic",
			tokenOpts: []TestOption{TestPeriodicToken(false)},
			wantErr:   errors.VaultTokenNotPeriodic,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			ctx := context.Background()
			kms := kms.TestKms(t, conn, wrapper)
			repo, err := NewRepository(ctx, rw, rw, kms, sche)
			require.NoError(err)
			require.NotNil(repo)
			_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
			err = RegisterJobs(ctx, sche, rw, rw, kms)
			require.NoError(err)

			v := NewTestVaultServer(t, WithTestVaultTLS(tt.tls))
			_, token := v.CreateToken(t, tt.tokenOpts...)

			var opts []Option
			if tt.tls == TestServerTLS {
				opts = append(opts, WithCACert(v.CaCert))
			}
			if tt.tls == TestClientTLS {
				opts = append(opts, WithCACert(v.CaCert))
				clientCert, err := NewClientCertificate(ctx, v.ClientCert, v.ClientKey)
				require.NoError(err)
				opts = append(opts, WithClientCert(clientCert))
			}

			credStoreIn, err := NewCredentialStore(prj.GetPublicId(), v.Addr, []byte(token), opts...)
			assert.NoError(err)
			require.NotNil(credStoreIn)
			got, err := repo.CreateCredentialStore(ctx, credStoreIn)

			if tt.wantErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantErr), err), "want err: %q got: %q", tt.wantErr, err)
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
			assertPublicId(t, globals.VaultCredentialStorePrefix, got.PublicId)
			assert.NotSame(credStoreIn, got)
			assert.Equal(got.CreateTime, got.UpdateTime)
			assert.NoError(db.TestVerifyOplog(t, rw, got.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second)))

			outToken := allocToken()
			assert.NoError(rw.LookupWhere(ctx, &outToken, "store_id = ?", []any{got.PublicId}))

			if tt.tls == TestClientTLS {
				outClientCert := allocClientCertificate()
				assert.NoError(rw.LookupWhere(ctx, &outClientCert, "store_id = ?", []any{got.PublicId}))
			}
		})
	}
}

func TestRepository_LookupCredentialStore(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	sche := scheduler.TestScheduler(t, conn, wrapper)

	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	stores := TestCredentialStores(t, conn, wrapper, prj.PublicId, 3)
	csWithClientCert := stores[0]
	csWithoutClientCert := stores[1]
	csWithExpiredToken := stores[2]

	ccert := allocClientCertificate()
	ccert.StoreId = csWithoutClientCert.GetPublicId()
	rows, err := rw.Delete(ctx, ccert, db.WithWhere("store_id = ?", csWithoutClientCert.GetPublicId()))
	require.NoError(t, err)
	require.Equal(t, 1, rows)

	rows, err = rw.Exec(ctx,
		"update credential_vault_token set status = ? where token_hmac = ?",
		[]any{ExpiredToken, csWithExpiredToken.Token().TokenHmac})
	require.NoError(t, err)
	require.Equal(t, 1, rows)

	badId, err := newCredentialStoreId(ctx)
	assert.NoError(t, err)
	require.NotNil(t, badId)

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
			name:           "valid-with-expired-token",
			id:             csWithExpiredToken.GetPublicId(),
			want:           csWithExpiredToken,
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
			kms := kms.TestKms(t, conn, wrapper)
			repo, err := NewRepository(ctx, rw, rw, kms, sche)
			assert.NoError(err)
			require.NotNil(repo)
			err = RegisterJobs(ctx, sche, rw, rw, kms)
			require.NoError(err)

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

func TestRepository_UpdateCredentialStore_Attributes(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	sche := scheduler.TestScheduler(t, conn, wrapper)

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
		wantErr   errors.Code
	}{
		{
			name: "nil-credential-store",
			orig: &CredentialStore{
				CredentialStore: &store.CredentialStore{},
			},
			chgFn:   makeNil(),
			masks:   []string{"Name", "Description"},
			wantErr: errors.InvalidParameter,
		},
		{
			name: "nil-embedded-credential-store",
			orig: &CredentialStore{
				CredentialStore: &store.CredentialStore{},
			},
			chgFn:   makeEmbeddedNil(),
			masks:   []string{"Name", "Description"},
			wantErr: errors.InvalidParameter,
		},
		{
			name: "no-public-id",
			orig: &CredentialStore{
				CredentialStore: &store.CredentialStore{},
			},
			chgFn:   deletePublicId(),
			masks:   []string{"Name", "Description"},
			wantErr: errors.InvalidPublicId,
		},
		{
			name: "updating-non-existent-credential-store",
			orig: &CredentialStore{
				CredentialStore: &store.CredentialStore{
					Name: "test-name-repo",
				},
			},
			chgFn:   combine(nonExistentPublicId(), changeName("test-update-name-repo")),
			masks:   []string{"Name"},
			wantErr: errors.RecordNotFound,
		},
		{
			name: "empty-field-mask",
			orig: &CredentialStore{
				CredentialStore: &store.CredentialStore{
					Name: "test-name-repo",
				},
			},
			chgFn:   changeName("test-update-name-repo"),
			wantErr: errors.EmptyFieldMask,
		},
		{
			name: "read-only-fields-in-field-mask",
			orig: &CredentialStore{
				CredentialStore: &store.CredentialStore{
					Name: "test-name-repo",
				},
			},
			chgFn:   changeName("test-update-name-repo"),
			masks:   []string{"PublicId", "CreateTime", "UpdateTime", "ProjectId"},
			wantErr: errors.InvalidFieldMask,
		},
		{
			name: "unknown-field-in-field-mask",
			orig: &CredentialStore{
				CredentialStore: &store.CredentialStore{
					Name: "test-name-repo",
				},
			},
			chgFn:   changeName("test-update-name-repo"),
			masks:   []string{"Bilbo"},
			wantErr: errors.InvalidFieldMask,
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
			masks: []string{"Namespace"},
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
			masks: []string{"Namespace"},
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
			repo, err := NewRepository(ctx, rw, rw, kms, sche)
			assert.NoError(err)
			require.NotNil(repo)
			err = RegisterJobs(ctx, sche, rw, rw, kms)
			require.NoError(err)

			_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
			tt.orig.ProjectId = prj.GetPublicId()

			vs := NewTestVaultServer(t)

			tt.orig.VaultAddress = vs.Addr
			if tt.want != nil && tt.want.VaultAddress == "" {
				tt.want.VaultAddress = vs.Addr
			}

			_, token := vs.CreateToken(t)
			tt.orig.inputToken = []byte(token)

			orig, err := repo.CreateCredentialStore(ctx, tt.orig)
			assert.NoError(err)
			require.NotNil(orig)

			if tt.chgFn != nil {
				orig = tt.chgFn(orig)
			}
			got, gotCount, err := repo.UpdateCredentialStore(ctx, orig, 1, tt.masks)
			if tt.wantErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantErr), err), "want err: %q got: %q", tt.wantErr, err)
				assert.Equal(tt.wantCount, gotCount, "row count")
				assert.Nil(got)
				return
			}
			assert.NoError(err)
			assert.Empty(tt.orig.PublicId)
			require.NotNil(got)
			assertPublicId(t, globals.VaultCredentialStorePrefix, got.PublicId)
			assert.Equal(tt.wantCount, gotCount, "row count")
			assert.NotSame(tt.orig, got)
			assert.Equal(tt.orig.ProjectId, got.ProjectId)
			underlyingDB, err := conn.SqlDB(ctx)
			require.NoError(err)
			dbassert := dbassert.New(t, underlyingDB)
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

			assert.Equal(tt.want.VaultAddress, got.VaultAddress)

			if tt.wantCount > 0 {
				assert.NoError(db.TestVerifyOplog(t, rw, got.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second)))
			}
		})
	}

	t.Run("change-vault-address", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		ctx := context.Background()
		kms := kms.TestKms(t, conn, wrapper)
		repo, err := NewRepository(ctx, rw, rw, kms, sche)
		assert.NoError(err)
		require.NotNil(repo)
		err = RegisterJobs(ctx, sche, rw, rw, kms)
		require.NoError(err)

		vs := NewTestVaultServer(t)
		_, token := vs.CreateToken(t)

		u, err := url.Parse(vs.Addr)
		require.NoError(err)
		_, port, err := net.SplitHostPort(u.Host)
		require.NoError(err)

		_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		in := &CredentialStore{
			inputToken: []byte(token),
			CredentialStore: &store.CredentialStore{
				ProjectId:    prj.GetPublicId(),
				VaultAddress: fmt.Sprintf("%v://127.0.0.1:%s", u.Scheme, port),
			},
		}

		orig, err := repo.CreateCredentialStore(ctx, in)
		assert.NoError(err)
		require.NotNil(orig)

		// Change Address 127.0.0.1:port -> localhost:port should work
		orig.VaultAddress = fmt.Sprintf("%v://localhost:%s", u.Scheme, port)
		got, gotCount, err := repo.UpdateCredentialStore(ctx, orig, 1, []string{vaultAddressField})
		assert.NoError(err)
		assert.Equal(1, gotCount, "count of updated records")
		require.NotNil(got)
		assert.Equal(orig.VaultAddress, got.VaultAddress)

		// Update to new address should fail because current token not valid on new address
		origAddr := orig.VaultAddress
		orig.VaultAddress = "https://vault2.nowhere.com"
		got, gotCount, err = repo.UpdateCredentialStore(ctx, orig, 2, []string{vaultAddressField})
		assert.Error(err)
		require.Nil(got)
		require.Equal(0, gotCount)

		cs, err := repo.LookupCredentialStore(ctx, orig.PublicId)
		require.NoError(err)
		assert.Equal(origAddr, cs.VaultAddress)
	})

	t.Run("change-ca-cert", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		ctx := context.Background()
		kms := kms.TestKms(t, conn, wrapper)
		repo, err := NewRepository(ctx, rw, rw, kms, sche)
		assert.NoError(err)
		require.NotNil(repo)
		err = RegisterJobs(ctx, sche, rw, rw, kms)
		require.NoError(err)

		vs := NewTestVaultServer(t, WithTestVaultTLS(TestServerTLS))

		_, token := vs.CreateToken(t)

		_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		in := &CredentialStore{
			inputToken: []byte(token),
			CredentialStore: &store.CredentialStore{
				ProjectId:    prj.GetPublicId(),
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
		got1, gotCount1, err := repo.UpdateCredentialStore(ctx, orig, 1, []string{"CaCert"})
		assert.NoError(err)
		assert.Equal(1, gotCount1, "count of updated records")
		require.NotNil(got1)
		assert.Equal(vs.ServerCert, got1.CaCert)

		// Delete CA Cert
		orig.CaCert = nil
		got2, gotCount2, err := repo.UpdateCredentialStore(ctx, orig, 2, []string{"CaCert"})
		assert.NoError(err)
		assert.Equal(1, gotCount2, "count of updated records")
		require.NotNil(got2)
		assert.Nil(got2.CaCert)
		underlyingDB, err := conn.SqlDB(ctx)
		require.NoError(err)
		dbassert := dbassert.New(t, underlyingDB)
		dbassert.IsNull(got2, "CaCert")
	})

	t.Run("invalid-duplicate-names", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		ctx := context.Background()
		kms := kms.TestKms(t, conn, wrapper)
		repo, err := NewRepository(ctx, rw, rw, kms, sche)
		assert.NoError(err)
		require.NotNil(repo)
		err = RegisterJobs(ctx, sche, rw, rw, kms)
		require.NoError(err)

		name := "test-dup-name"
		_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		css := TestCredentialStores(t, conn, wrapper, prj.PublicId, 2)

		csA, csB := css[0], css[1]

		csA.Name = name
		got1, gotCount1, err := repo.UpdateCredentialStore(ctx, csA, 1, []string{"Name"})
		assert.NoError(err)
		require.NotNil(got1)
		assert.Equal(name, got1.Name)
		assert.Equal(1, gotCount1, "row count")
		assert.NoError(db.TestVerifyOplog(t, rw, csA.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second)))

		csB.Name = name
		got2, gotCount2, err := repo.UpdateCredentialStore(ctx, csB, 1, []string{"Name"})
		assert.Truef(errors.Match(errors.T(errors.NotUnique), err), "want err code: %v got err: %v", errors.NotUnique, err)
		assert.Nil(got2)
		assert.Equal(db.NoRowsAffected, gotCount2, "row count")
	})

	t.Run("valid-duplicate-names-diff-projects", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		ctx := context.Background()
		kms := kms.TestKms(t, conn, wrapper)
		repo, err := NewRepository(ctx, rw, rw, kms, sche)
		assert.NoError(err)
		require.NotNil(repo)
		err = RegisterJobs(ctx, sche, rw, rw, kms)
		require.NoError(err)

		vs := NewTestVaultServer(t)

		_, token1 := vs.CreateToken(t)
		_, token2 := vs.CreateToken(t)

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

		in.ProjectId = prj.GetPublicId()
		got, err := repo.CreateCredentialStore(ctx, in)
		assert.NoError(err)
		require.NotNil(got)
		assertPublicId(t, globals.VaultCredentialStorePrefix, got.PublicId)
		assert.NotSame(in, got)
		assert.Equal(in.Name, got.Name)
		assert.Equal(in.Description, got.Description)

		prj2 := iam.TestProject(t, iam.TestRepo(t, conn, wrapper), org.GetPublicId())
		in2.ProjectId = prj2.GetPublicId()
		in2.Name = "first-name"
		got2, err := repo.CreateCredentialStore(ctx, in2)
		assert.NoError(err)
		require.NotNil(got2)
		got2.Name = got.Name
		got3, gotCount3, err := repo.UpdateCredentialStore(ctx, got2, 1, []string{"Name"})
		assert.NoError(err)
		require.NotNil(got3)
		assert.NotSame(got2, got3)
		assert.Equal(got.Name, got3.Name)
		assert.Equal(got2.Description, got3.Description)
		assert.Equal(1, gotCount3, "row count")
	})

	t.Run("change-project-id", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		ctx := context.Background()
		kms := kms.TestKms(t, conn, wrapper)
		repo, err := NewRepository(ctx, rw, rw, kms, sche)
		assert.NoError(err)
		require.NotNil(repo)
		err = RegisterJobs(ctx, sche, rw, rw, kms)
		require.NoError(err)

		iamRepo := iam.TestRepo(t, conn, wrapper)
		org, prj1 := iam.TestScopes(t, iamRepo)
		prj2 := iam.TestProject(t, iamRepo, org.GetPublicId())
		csA, csB := TestCredentialStores(t, conn, wrapper, prj1.PublicId, 1)[0], TestCredentialStores(t, conn, wrapper, prj2.PublicId, 1)[0]
		assert.NotEqual(csA.ProjectId, csB.ProjectId)
		orig := csA.clone()

		csA.ProjectId = csB.ProjectId
		assert.Equal(csA.ProjectId, csB.ProjectId)

		got1, gotCount1, err := repo.UpdateCredentialStore(ctx, csA, 1, []string{"Name"})

		assert.NoError(err)
		require.NotNil(got1)
		assert.Equal(orig.ProjectId, got1.ProjectId)
		assert.Equal(1, gotCount1, "row count")
	})
}

func TestRepository_UpdateCredentialStore_VaultToken(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	sche := scheduler.TestScheduler(t, conn, wrapper)

	tests := []struct {
		name               string
		newTokenOpts       []TestOption
		wantOldTokenStatus TokenStatus
		updateToken        func(ctx context.Context, tokenHmac []byte)
		wantCount          int
		wantErr            errors.Code
	}{
		{
			name:               "valid",
			wantOldTokenStatus: MaintainingToken,
			wantCount:          1,
		},
		{
			name:               "valid-token-expired",
			wantOldTokenStatus: ExpiredToken,
			updateToken: func(ctx context.Context, tokenHmac []byte) {
				_, err := rw.Exec(ctx,
					"update credential_vault_token set status = ? where token_hmac = ?",
					[]any{ExpiredToken, tokenHmac})
				require.NoError(t, err)
			},
			wantCount: 1,
		},
		{
			name:         "token-missing-capabilities",
			newTokenOpts: []TestOption{WithPolicies([]string{"default"})},
			wantErr:      errors.VaultTokenMissingCapabilities,
		},
		{
			name:         "token-not-renewable",
			newTokenOpts: []TestOption{TestRenewableToken(false)},
			wantErr:      errors.VaultTokenNotRenewable,
		},
		{
			name:         "token-not-orphan",
			newTokenOpts: []TestOption{TestOrphanToken(false)},
			wantErr:      errors.VaultTokenNotOrphan,
		},
		{
			name:         "token-not-periodic",
			newTokenOpts: []TestOption{TestPeriodicToken(false)},
			wantErr:      errors.VaultTokenNotPeriodic,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			ctx := context.Background()
			kms := kms.TestKms(t, conn, wrapper)
			repo, err := NewRepository(ctx, rw, rw, kms, sche)
			require.NoError(err)
			require.NotNil(repo)
			_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
			err = RegisterJobs(ctx, sche, rw, rw, kms)
			require.NoError(err)

			v := NewTestVaultServer(t)
			_, origToken := v.CreateToken(t)

			// create
			origIn, err := NewCredentialStore(prj.GetPublicId(), v.Addr, []byte(origToken))
			assert.NoError(err)
			require.NotNil(origIn)

			orig, err := repo.CreateCredentialStore(ctx, origIn)
			assert.NoError(err)
			require.NotNil(orig)

			if tt.updateToken != nil {
				tt.updateToken(ctx, orig.outputToken.TokenHmac)
			}

			// update
			_, updateToken := v.CreateToken(t, tt.newTokenOpts...)

			updateIn, err := NewCredentialStore(prj.GetPublicId(), v.Addr, []byte(updateToken))
			assert.NoError(err)
			require.NotNil(updateIn)
			updateIn.PublicId = orig.GetPublicId()
			got, gotCount, err := repo.UpdateCredentialStore(ctx, updateIn, 1, []string{"Token"})
			if tt.wantErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantErr), err), "want err: %q got: %q", tt.wantErr, err)
				assert.Equal(tt.wantCount, gotCount, "row count")
				assert.Nil(got)
				return
			}
			require.NoError(err)
			assert.Equal(tt.wantCount, gotCount)
			assert.NotNil(got)

			var tokens []*Token
			require.NoError(rw.SearchWhere(ctx, &tokens, "store_id = ?", []any{orig.GetPublicId()}))
			assert.Len(tokens, 2)
			assert.Equal(string(tt.wantOldTokenStatus), tokens[0].Status)

			lookup, err := repo.LookupCredentialStore(ctx, orig.GetPublicId())
			assert.NoError(err)
			require.NotNil(lookup)
			require.NotNil(orig.outputToken)
			require.NotNil(got.outputToken)
			assert.NotEqual(orig.outputToken.TokenHmac, got.outputToken.TokenHmac)
		})
	}
}

func TestRepository_UpdateCredentialStore_ClientCert(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	sche := scheduler.TestScheduler(t, conn, wrapper)

	existingClientCert := func(t *testing.T, v *TestVaultServer) *ClientCertificate {
		clientCert, err := NewClientCertificate(context.Background(), v.ClientCert, v.ClientKey)
		require.NoError(t, err)
		return clientCert
	}

	newClientCert := func(t *testing.T, v *TestVaultServer) *ClientCertificate {
		cb := testClientCert(t, v.clientCertBundle.CA)
		return cb.Cert.ClientCertificate(t)
	}

	// newClientCertFromServerCA  is useful for when v is configured with
	// TestServerTLS. It uses the server CA to create a new client
	// certificate since the v will not have a clientCertBundle.
	newClientCertFromServerCA := func(t *testing.T, v *TestVaultServer) *ClientCertificate {
		cb := testClientCert(t, v.serverCertBundle.CA)
		return cb.Cert.ClientCertificate(t)
	}

	nilClientCert := func(t *testing.T, v *TestVaultServer) *ClientCertificate {
		return nil
	}

	assertUpdated := func(t *testing.T, org, updated *ClientCertificate, ps *clientStore) {
		assert.Equal(t, updated.Certificate, ps.ClientCert, "updated certificate")
		assert.Equal(t, updated.CertificateKey, []byte(ps.ClientKey), "updated certificate key")
	}

	assertDeleted := func(t *testing.T, org, updated *ClientCertificate, ps *clientStore) {
		assert.Nil(t, updated, "updated certificate")
		assert.Nil(t, ps.ClientCert, "ps ClientCert")
		assert.Nil(t, ps.ClientKey, "ps ClientKey")
		assert.Nil(t, ps.CtClientKey, "ps CtClientKey")
	}

	tests := []struct {
		name      string
		tls       TestVaultTLS
		origFn    func(t *testing.T, v *TestVaultServer) *ClientCertificate
		updateFn  func(t *testing.T, v *TestVaultServer) *ClientCertificate
		wantFn    func(t *testing.T, org, updated *ClientCertificate, ps *clientStore)
		wantCount int
		wantErr   errors.Code
	}{
		{
			name:      "ClientCert-to-ClientCert",
			tls:       TestClientTLS,
			origFn:    existingClientCert,
			updateFn:  newClientCert,
			wantFn:    assertUpdated,
			wantCount: 1,
		},
		{
			name:      "ClientCert-to-null",
			tls:       TestClientTLS,
			origFn:    existingClientCert,
			updateFn:  nilClientCert,
			wantFn:    assertDeleted,
			wantCount: 1,
		},
		{
			name:      "null-to-ClientCert",
			tls:       TestServerTLS,
			origFn:    nilClientCert,
			updateFn:  newClientCertFromServerCA,
			wantFn:    assertUpdated,
			wantCount: 1,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			ctx := context.Background()
			kms := kms.TestKms(t, conn, wrapper)
			repo, err := NewRepository(ctx, rw, rw, kms, sche)
			require.NoError(err)
			require.NotNil(repo)
			_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
			err = RegisterJobs(ctx, sche, rw, rw, kms)
			require.NoError(err)

			v := NewTestVaultServer(t, WithTestVaultTLS(tt.tls))

			var opts []Option
			if tt.tls == TestServerTLS {
				opts = append(opts, WithCACert(v.CaCert))
			}
			if tt.tls == TestClientTLS {
				opts = append(opts, WithCACert(v.CaCert))
				clientCert, err := NewClientCertificate(ctx, v.ClientCert, v.ClientKey)
				require.NoError(err)
				opts = append(opts, WithClientCert(clientCert))
			}

			_, origToken := v.CreateToken(t)
			origClientCert := tt.origFn(t, v)
			opts = append(opts, WithClientCert(origClientCert))

			// create
			origIn, err := NewCredentialStore(prj.GetPublicId(), v.Addr, []byte(origToken), opts...)
			assert.NoError(err)
			require.NotNil(origIn)

			orig, err := repo.CreateCredentialStore(ctx, origIn)
			assert.NoError(err)
			require.NotNil(orig)

			// update
			updateClientCert := tt.updateFn(t, v)

			updateIn, err := NewCredentialStore(prj.GetPublicId(), v.Addr, []byte("ignore"), WithClientCert(updateClientCert))
			assert.NoError(err)
			require.NotNil(updateIn)
			updateIn.PublicId = orig.GetPublicId()
			got, gotCount, err := repo.UpdateCredentialStore(ctx, updateIn, 1, []string{"Certificate", "CertificateKey"})
			assert.Equal(tt.wantCount, gotCount, "row count")
			if tt.wantErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantErr), err), "want err: %q got: %q", tt.wantErr, err)
				assert.Nil(got)
				return
			}
			require.NoError(err)
			assert.NotNil(got)

			ps, err := repo.lookupClientStore(ctx, orig.GetPublicId())
			require.NoError(err)
			tt.wantFn(t, origClientCert, updateClientCert, ps)
		})
	}
}

func TestRepository_DeleteCredentialStore(t *testing.T) {
	type tokenCount struct {
		current, maintaining int
		revoke               int
		revoked, expired     int
	}

	type tokenMap map[string]*tokenCount

	type setupFn func(t *testing.T, conn *db.DB) (storeId string, libs []*CredentialLibrary, tokens tokenMap, repo *Repository)

	baseSetup := func(t *testing.T, conn *db.DB) (wrapper wrapping.Wrapper, repo *Repository, projectId string) {
		wrapper = db.TestWrapper(t)
		kms := kms.TestKms(t, conn, wrapper)
		sche := scheduler.TestScheduler(t, conn, wrapper)
		rw := db.New(conn)
		repo, err := NewRepository(context.Background(), rw, rw, kms, sche)
		require.NoError(t, err)
		require.NotNil(t, repo)
		err = RegisterJobs(context.Background(), sche, rw, rw, kms)
		require.NoError(t, err)

		_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		projectId = prj.GetPublicId()
		return wrapper, repo, projectId
	}

	testStores := func(t *testing.T, conn *db.DB, wrapper wrapping.Wrapper, tokens tokenMap, projectId string, count int) ([]*CredentialStore, tokenMap) {
		if tokens == nil {
			tokens = make(tokenMap)
		}
		css := TestCredentialStores(t, conn, wrapper, projectId, count)
		for _, cs := range css {
			storeId := cs.GetPublicId()
			tokens[storeId] = new(tokenCount)
			tokens[storeId].current = 1
		}
		return css, tokens
	}

	makeMaintainingTokens := func(t *testing.T, conn *db.DB, wrapper wrapping.Wrapper, tokens tokenMap, projectId, storeId string, count int) tokenMap {
		testTokens(t, conn, wrapper, projectId, storeId, count)
		tokens[storeId].maintaining = count
		return tokens
	}

	makeRevokedTokens := func(t *testing.T, conn *db.DB, wrapper wrapping.Wrapper, tokens tokenMap, projectId, storeId string, count int) tokenMap {
		require.NotNil(t, tokens)
		const query = `
update credential_vault_token
   set status   = 'revoked'
 where store_id = ?
   and status   = 'current';
`
		t.Helper()
		rw := db.New(conn)
		ctx := context.Background()

		for i := 0; i < count; i++ {
			rows, err := rw.Exec(ctx, query, []any{storeId})
			require.Equal(t, 1, rows)
			require.NoError(t, err)
			tokens[storeId].revoked++
			testTokens(t, conn, wrapper, projectId, storeId, 1)
		}
		return tokens
	}

	makeExpiredTokens := func(t *testing.T, conn *db.DB, wrapper wrapping.Wrapper, tokens tokenMap, projectId, storeId string, count int) tokenMap {
		require.NotNil(t, tokens)
		const query = `
update credential_vault_token
   set status   = 'expired'
 where store_id = ?
   and status   = 'current';
`
		t.Helper()
		rw := db.New(conn)
		ctx := context.Background()

		for i := 0; i < count; i++ {
			rows, err := rw.Exec(ctx, query, []any{storeId})
			require.Equal(t, 1, rows)
			require.NoError(t, err)
			tokens[storeId].expired++
			testTokens(t, conn, wrapper, projectId, storeId, 1)
		}
		return tokens
	}

	assertTokens := func(t *testing.T, conn *db.DB, want tokenMap) {
		const query = `
  select store_id, status, count(token_hmac)
    from credential_vault_token
group by store_id, status;
`

		rw := db.New(conn)
		got := make(tokenMap, len(want))
		for id := range want {
			got[id] = new(tokenCount)
		}

		var (
			id     string
			status string
			count  int
		)

		ctx := context.Background()
		rows, err := rw.Query(ctx, query, nil)
		require.NoError(t, err)
		defer rows.Close()
		for rows.Next() {
			require.NoError(t, rows.Scan(&id, &status, &count))
			switch status {
			case "current":
				got[id].current = count
			case "maintaining":
				got[id].maintaining = count
			case "revoke":
				got[id].revoke = count
			case "revoked":
				got[id].revoked = count
			case "expired":
				got[id].expired = count
			default:
				assert.Failf(t, "Unexpected status: %s", status)
			}
		}
		require.NoError(t, rows.Err())
		assert.Equal(t, want, got)
	}

	tests := []struct {
		name  string
		setup setupFn
	}{
		{
			name: "simple",
			setup: func(t *testing.T, conn *db.DB) (storeId string, libs []*CredentialLibrary, tokens tokenMap, repo *Repository) {
				wrapper, repo, projectId := baseSetup(t, conn)
				css, tokens := testStores(t, conn, wrapper, nil, projectId, 1)
				cs := css[0]
				storeId = cs.GetPublicId()
				return storeId, libs, tokens, repo
			},
		},
		{
			name: "with-libraries",
			setup: func(t *testing.T, conn *db.DB) (storeId string, libs []*CredentialLibrary, tokens tokenMap, repo *Repository) {
				wrapper, repo, projectId := baseSetup(t, conn)
				css, tokens := testStores(t, conn, wrapper, nil, projectId, 1)
				cs := css[0]
				storeId = cs.GetPublicId()

				libs = TestCredentialLibraries(t, conn, wrapper, storeId, globals.UnspecifiedCredentialType, 4)
				return storeId, libs, tokens, repo
			},
		},
		{
			name: "with-maintaining-tokens",
			setup: func(t *testing.T, conn *db.DB) (storeId string, libs []*CredentialLibrary, tokens tokenMap, repo *Repository) {
				wrapper, repo, projectId := baseSetup(t, conn)
				css, tokens := testStores(t, conn, wrapper, nil, projectId, 1)
				cs := css[0]
				storeId = cs.GetPublicId()

				libs = TestCredentialLibraries(t, conn, wrapper, storeId, globals.UnspecifiedCredentialType, 4)
				tokens = makeMaintainingTokens(t, conn, wrapper, tokens, projectId, storeId, 4)
				return storeId, libs, tokens, repo
			},
		},
		{
			name: "with-revoked-tokens",
			setup: func(t *testing.T, conn *db.DB) (storeId string, libs []*CredentialLibrary, tokens tokenMap, repo *Repository) {
				wrapper, repo, projectId := baseSetup(t, conn)
				css, tokens := testStores(t, conn, wrapper, nil, projectId, 1)
				cs := css[0]
				storeId = cs.GetPublicId()

				libs = TestCredentialLibraries(t, conn, wrapper, storeId, globals.UnspecifiedCredentialType, 4)
				tokens = makeRevokedTokens(t, conn, wrapper, tokens, projectId, storeId, 4)
				return storeId, libs, tokens, repo
			},
		},
		{
			name: "with-expired-tokens",
			setup: func(t *testing.T, conn *db.DB) (storeId string, libs []*CredentialLibrary, tokens tokenMap, repo *Repository) {
				wrapper, repo, projectId := baseSetup(t, conn)
				css, tokens := testStores(t, conn, wrapper, nil, projectId, 1)
				cs := css[0]
				storeId = cs.GetPublicId()

				libs = TestCredentialLibraries(t, conn, wrapper, storeId, globals.UnspecifiedCredentialType, 4)
				tokens = makeExpiredTokens(t, conn, wrapper, tokens, projectId, storeId, 4)
				return storeId, libs, tokens, repo
			},
		},
		{
			name: "with-all-token-statuses",
			setup: func(t *testing.T, conn *db.DB) (storeId string, libs []*CredentialLibrary, tokens tokenMap, repo *Repository) {
				wrapper, repo, projectId := baseSetup(t, conn)
				css, tokens := testStores(t, conn, wrapper, nil, projectId, 1)
				cs := css[0]
				storeId = cs.GetPublicId()

				libs = TestCredentialLibraries(t, conn, wrapper, storeId, globals.UnspecifiedCredentialType, 4)
				tokens = makeMaintainingTokens(t, conn, wrapper, tokens, projectId, storeId, 2)
				tokens = makeRevokedTokens(t, conn, wrapper, tokens, projectId, storeId, 3)
				tokens = makeExpiredTokens(t, conn, wrapper, tokens, projectId, storeId, 5)
				return storeId, libs, tokens, repo
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert, require := assert.New(t), require.New(t)
			conn, _ := db.TestSetup(t, "postgres")
			ctx := context.Background()

			storeId, actualLibs, tokens, repo := tt.setup(t, conn)

			var credStore *CredentialStore
			var projectId string

			assertTokens(t, conn, tokens)
			{
				lookup, err := repo.LookupCredentialStore(ctx, storeId)
				assert.NoError(err)
				require.NotNil(lookup)
				assert.Nil(lookup.DeleteTime)
				projectId = lookup.GetProjectId()
				credStore = lookup
			}

			{
				libs, _, err := repo.ListLibraries(ctx, storeId)
				assert.NoError(err)
				assert.Len(libs, len(actualLibs))
			}

			// verify no revoke stores exist
			{
				rows, err := repo.reader.Query(ctx,
					"select * from credential_vault_token_renewal_revocation where token_status = $1",
					[]any{ExpiredToken})
				require.NoError(err)
				defer rows.Close()
				assert.False(rows.Next())
			}

			// verify updating the credential store works
			{
				masks := []string{"Name"}
				credStore.Name = "test name"
				updatedStore, updatedCount, err := repo.UpdateCredentialStore(ctx, credStore, credStore.Version, masks)
				assert.NoError(err)
				assert.Equal(1, updatedCount)
				assert.NotNil(updatedStore)
				credStore = updatedStore
			}

			// delete
			{
				deletedCount, err := repo.DeleteCredentialStore(ctx, storeId)
				assert.NoError(err)
				assert.Equal(1, deletedCount)
			}

			// All current and maintaining tokens should now be in the
			// 'revoke' status. The status of any other tokens should be
			// unchanged.
			tokens[storeId].revoke = tokens[storeId].current + tokens[storeId].maintaining
			tokens[storeId].current, tokens[storeId].maintaining = 0, 0
			assertTokens(t, conn, tokens)

			// should not be in lookup
			{
				lookup, err := repo.LookupCredentialStore(ctx, storeId)
				assert.NoError(err)
				assert.Nil(lookup)
			}

			// libraries should be empty
			{
				libs, _, err := repo.ListLibraries(ctx, storeId)
				assert.NoError(err)
				assert.Empty(libs)
			}

			// creating a library should fail
			{
				newLib := &CredentialLibrary{
					CredentialLibrary: &store.CredentialLibrary{
						StoreId:    storeId,
						HttpMethod: "GET",
						VaultPath:  "/some/path",
					},
				}
				lib, err := repo.CreateCredentialLibrary(ctx, projectId, newLib)
				assert.Error(err)
				assert.Nil(lib)
			}

			var deleteTime *timestamp.Timestamp
			// still in clientStore delete time set
			{
				rows, err := repo.reader.Query(ctx,
					"select * from credential_vault_token_renewal_revocation where token_status = $1",
					[]any{RevokeToken})
				require.NoError(err)
				defer rows.Close()

				var privateStore *clientStore
				var storeIds []string
				for rows.Next() {
					var s clientStore
					err = repo.reader.ScanRows(ctx, rows, &s)
					require.NoError(err)
					require.NotNil(s)

					id := s.GetPublicId()
					storeIds = append(storeIds, id)
					if id == storeId {
						privateStore = &s
						break
					}
				}
				assert.NoError(rows.Err())
				assert.Contains(storeIds, storeId)
				require.NotNil(privateStore)
				if assert.NotNil(privateStore.DeleteTime) {
					deleteTime = privateStore.DeleteTime
				}
			}

			// updating a soft deleted credential store should not work
			{
				masks := []string{"Name"}
				credStore.Name = "second test name"
				updatedStore, updatedCount, err := repo.UpdateCredentialStore(ctx, credStore, credStore.Version, masks)
				assert.Error(err)
				assert.Equal(0, updatedCount)
				assert.Nil(updatedStore)
			}

			// calling delete again should not change anything
			{
				deleteCount, err := repo.DeleteCredentialStore(ctx, storeId)
				assert.NoError(err)
				assert.Equal(0, deleteCount)
			}

			// still in clientStore delete time should not change
			{
				rows, err := repo.reader.Query(ctx,
					"select * from credential_vault_token_renewal_revocation where token_status = $1",
					[]any{RevokeToken})
				require.NoError(err)
				defer rows.Close()

				var privateStore *clientStore
				var storeIds []string
				for rows.Next() {
					var s clientStore
					err = repo.reader.ScanRows(ctx, rows, &s)
					require.NoError(err)
					require.NotNil(s)

					id := s.GetPublicId()
					storeIds = append(storeIds, id)
					if id == storeId {
						privateStore = &s
						break
					}
				}
				assert.NoError(rows.Err())
				assert.Contains(storeIds, storeId)
				require.NotNil(privateStore)
				assert.Empty(cmp.Diff(deleteTime, privateStore.DeleteTime, protocmp.Transform()))
			}
		})
	}
}
