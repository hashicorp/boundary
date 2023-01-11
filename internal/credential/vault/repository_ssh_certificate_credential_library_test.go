package vault

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/credential/vault/store"
	"github.com/hashicorp/boundary/internal/db"
	dbassert "github.com/hashicorp/boundary/internal/db/assert"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/scheduler"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRepository_CreateSSHCertificateCredentialLibrary(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)

	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	cs := TestCredentialStores(t, conn, wrapper, prj.GetPublicId(), 1)[0]

	tests := []struct {
		name    string
		in      *SSHCertificateCredentialLibrary
		opts    []Option
		want    *SSHCertificateCredentialLibrary
		wantErr errors.Code
	}{
		{
			name:    "nil-SSHCertificateCredentialLibrary",
			wantErr: errors.InvalidParameter,
		},
		{
			name:    "nil-embedded-SSHCertificateCredentialLibrary",
			in:      &SSHCertificateCredentialLibrary{},
			wantErr: errors.InvalidParameter,
		},
		{
			name: "invalid-no-store-id",
			in: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					VaultPath: "/some/path",
					Username:  "name",
				},
			},
			wantErr: errors.InvalidParameter,
		},
		{
			name: "invalid-public-id-set",
			in: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					StoreId:   cs.GetPublicId(),
					PublicId:  "abcd_OOOOOOOOOO",
					VaultPath: "/some/path",
					Username:  "name",
				},
			},
			wantErr: errors.InvalidParameter,
		},
		{
			name: "invalid-no-vault-path",
			in: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					StoreId:  cs.GetPublicId(),
					Username: "name",
				},
			},
			wantErr: errors.InvalidParameter,
		},
		{
			name: "invalid-no-username",
			in: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					StoreId:   cs.GetPublicId(),
					VaultPath: "/some/path",
				},
			},
			wantErr: errors.InvalidParameter,
		},
		{
			name: "valid-no-options",
			in: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					StoreId:   cs.GetPublicId(),
					VaultPath: "/some/path",
					Username:  "name",
				},
			},
			want: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					StoreId:   cs.GetPublicId(),
					VaultPath: "/some/path",
					Username:  "name",
					KeyType:   KeyTypeEd25519,
					KeyBits:   0,
				},
			},
		},
		{
			name: "valid-with-name",
			in: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					StoreId:   cs.GetPublicId(),
					Name:      "test-name-repo",
					VaultPath: "/some/path",
					Username:  "name",
					KeyBits:   0,
				},
			},
			want: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					StoreId:   cs.GetPublicId(),
					Name:      "test-name-repo",
					VaultPath: "/some/path",
					Username:  "name",
				},
			},
		},
		{
			name: "valid-with-description",
			in: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					StoreId:     cs.GetPublicId(),
					KeyType:     "ed25519",
					Description: "test-description-repo",
					VaultPath:   "/some/path",
					Username:    "name",
				},
			},
			want: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					StoreId:     cs.GetPublicId(),
					KeyType:     "ed25519",
					Description: "test-description-repo",
					VaultPath:   "/some/path",
					Username:    "name",
				},
			},
		},
		{
			name: "valid-key-type-key-bits-combination",
			in: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					StoreId:   cs.GetPublicId(),
					KeyType:   "ecdsa",
					KeyBits:   224,
					VaultPath: "/some/path",
					Username:  "name",
				},
			},
			want: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					StoreId:   cs.GetPublicId(),
					KeyType:   "ecdsa",
					KeyBits:   224,
					VaultPath: "/some/path",
					Username:  "name",
				},
			},
		},
		{
			name: "invalid-key-type-key-bits-combination",
			in: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					StoreId:   cs.GetPublicId(),
					KeyType:   "ecdsa",
					KeyBits:   2408,
					VaultPath: "/some/path",
					Username:  "name",
				},
			},
			wantErr: errors.NotSpecificIntegrity,
		},
		{
			name: "valid-critical-options",
			in: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					StoreId:         cs.GetPublicId(),
					VaultPath:       "/some/path",
					Username:        "name",
					CriticalOptions: "*",
				},
			},
			want: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					StoreId:         cs.GetPublicId(),
					VaultPath:       "/some/path",
					Username:        "name",
					CriticalOptions: "*",
				},
			},
		},
		{
			name: "valid-extensions",
			in: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					StoreId:    cs.GetPublicId(),
					VaultPath:  "/some/path",
					Username:   "name",
					Extensions: "permit-agent-forwarding, permit-pty",
				},
			},
			want: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					StoreId:    cs.GetPublicId(),
					VaultPath:  "/some/path",
					Username:   "name",
					Extensions: "permit-agent-forwarding, permit-pty",
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			ctx := context.Background()
			kms := kms.TestKms(t, conn, wrapper)
			sche := scheduler.TestScheduler(t, conn, wrapper)
			repo, err := NewRepository(rw, rw, kms, sche)
			require.NoError(err)
			require.NotNil(repo)
			got, err := repo.CreateSSHCertificateCredentialLibrary(ctx, prj.GetPublicId(), tt.in, tt.opts...)
			if tt.wantErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantErr), err), "want err: %q got: %q", tt.wantErr, err)
				assert.Nil(got)
				return
			}
			require.NoError(err)
			assert.Empty(tt.in.PublicId)
			require.NotNil(got)
			assertPublicId(t, SSHCertificateCredentialLibraryPrefix, got.GetPublicId())
			assert.NotSame(tt.in, got)
			assert.Equal(tt.want.Name, got.Name)
			assert.Equal(tt.want.Description, got.Description)
			assert.Equal(got.CredentialType(), credential.SshCertificateType)
			assert.Equal(got.CreateTime, got.UpdateTime)

			assert.NoError(db.TestVerifyOplog(t, rw, got.GetPublicId(), db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second)))
		})
	}

	t.Run("invalid-duplicate-names", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		ctx := context.Background()
		kms := kms.TestKms(t, conn, wrapper)
		sche := scheduler.TestScheduler(t, conn, wrapper)
		repo, err := NewRepository(rw, rw, kms, sche)
		require.NoError(err)
		require.NotNil(repo)
		_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		cs := TestCredentialStores(t, conn, wrapper, prj.GetPublicId(), 1)[0]
		in := &SSHCertificateCredentialLibrary{
			SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
				StoreId:   cs.GetPublicId(),
				KeyType:   "ed25519",
				VaultPath: "/some/path",
				Name:      "test-name-repo",
				Username:  "name",
			},
		}

		got, err := repo.CreateSSHCertificateCredentialLibrary(ctx, prj.GetPublicId(), in)
		require.NoError(err)
		require.NotNil(got)
		assertPublicId(t, SSHCertificateCredentialLibraryPrefix, got.GetPublicId())
		assert.NotSame(in, got)
		assert.Equal(in.Name, got.Name)
		assert.Equal(in.Description, got.Description)
		assert.Equal(got.CreateTime, got.UpdateTime)

		got2, err := repo.CreateSSHCertificateCredentialLibrary(ctx, prj.GetPublicId(), in)
		assert.Truef(errors.Match(errors.T(errors.NotUnique), err), "want err: %q got: %q", errors.NotUnique, err)
		assert.Nil(got2)
	})

	t.Run("valid-duplicate-names-diff-stores", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		ctx := context.Background()
		kms := kms.TestKms(t, conn, wrapper)
		sche := scheduler.TestScheduler(t, conn, wrapper)
		repo, err := NewRepository(rw, rw, kms, sche)
		require.NoError(err)
		require.NotNil(repo)

		_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		css := TestCredentialStores(t, conn, wrapper, prj.GetPublicId(), 2)

		csA, csB := css[0], css[1]

		in := &SSHCertificateCredentialLibrary{
			SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
				KeyType:   "ed25519",
				VaultPath: "/some/path",
				Name:      "test-name-repo",
				Username:  "name",
			},
		}
		in2 := in.clone()

		in.StoreId = csA.GetPublicId()
		got, err := repo.CreateSSHCertificateCredentialLibrary(ctx, prj.GetPublicId(), in)
		require.NoError(err)
		require.NotNil(got)
		assertPublicId(t, SSHCertificateCredentialLibraryPrefix, got.GetPublicId())
		assert.NotSame(in, got)
		assert.Equal(in.Name, got.Name)
		assert.Equal(in.Description, got.Description)
		assert.Equal(got.CreateTime, got.UpdateTime)

		in2.StoreId = csB.GetPublicId()
		got2, err := repo.CreateSSHCertificateCredentialLibrary(ctx, prj.GetPublicId(), in2)
		require.NoError(err)
		require.NotNil(got2)
		assertPublicId(t, SSHCertificateCredentialLibraryPrefix, got2.GetPublicId())
		assert.NotSame(in2, got2)
		assert.Equal(in2.Name, got2.Name)
		assert.Equal(in2.Description, got2.Description)
		assert.Equal(got2.CreateTime, got2.UpdateTime)
	})
}

func TestRepository_LookupSSHCertificateCredentialLibrary(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)

	{
		_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		css := TestCredentialStores(t, conn, wrapper, prj.GetPublicId(), 2)

		cs := css[0]
		csWithExpiredToken := css[1]
		rows, err := rw.Exec(context.Background(),
			"update credential_vault_token set status = ? where token_hmac = ?",
			[]any{ExpiredToken, csWithExpiredToken.Token().TokenHmac})
		require.NoError(t, err)
		require.Equal(t, 1, rows)

		tests := []struct {
			name string
			in   *SSHCertificateCredentialLibrary
		}{
			{
				name: "valid-no-options",
				in: &SSHCertificateCredentialLibrary{
					SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
						StoreId:   cs.GetPublicId(),
						VaultPath: "/some/path",
						Username:  "name",
					},
				},
			},

			{
				name: "valid-with-expired-cred-store-token",
				in: &SSHCertificateCredentialLibrary{
					SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
						StoreId:   csWithExpiredToken.GetPublicId(),
						VaultPath: "/some/path",
						Username:  "name",
					},
				},
			},
			{
				name: "valid-ssh-certificate-credential-type",
				in: &SSHCertificateCredentialLibrary{
					SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
						StoreId:        cs.GetPublicId(),
						VaultPath:      "/some/path",
						Username:       "name",
						CredentialType: string(credential.SshCertificateType),
					},
				},
			},
		}

		for _, tt := range tests {
			tt := tt
			t.Run(tt.name, func(t *testing.T) {
				// setup
				assert, require := assert.New(t), require.New(t)
				ctx := context.Background()
				kms := kms.TestKms(t, conn, wrapper)
				sche := scheduler.TestScheduler(t, conn, wrapper)
				repo, err := NewRepository(rw, rw, kms, sche)
				assert.NoError(err)
				require.NotNil(repo)
				orig, err := repo.CreateSSHCertificateCredentialLibrary(ctx, prj.GetPublicId(), tt.in)
				assert.NoError(err)
				require.NotEmpty(orig)
				// test
				got, err := repo.LookupSSHCertificateCredentialLibrary(ctx, orig.GetPublicId())
				assert.NoError(err)
				require.NotEmpty(got)
				assert.Equal(orig.Name, got.Name)
				assert.Equal(orig.Description, got.Description)
				assert.Equal(orig.CredentialType(), got.CredentialType())
			})
		}
	}

	t.Run("empty-public-id", func(t *testing.T) {
		// setup
		assert, require := assert.New(t), require.New(t)
		ctx := context.Background()
		kms := kms.TestKms(t, conn, wrapper)
		sche := scheduler.TestScheduler(t, conn, wrapper)
		repo, err := NewRepository(rw, rw, kms, sche)
		assert.NoError(err)
		require.NotNil(repo)
		// test
		got, err := repo.LookupCredentialLibrary(ctx, "")
		wantErr := errors.InvalidParameter
		assert.Truef(errors.Match(errors.T(wantErr), err), "want err: %q got: %q", wantErr, err)
		assert.Nil(got)
	})

	t.Run("not-found", func(t *testing.T) {
		// setup
		assert, require := assert.New(t), require.New(t)
		ctx := context.Background()
		kms := kms.TestKms(t, conn, wrapper)
		sche := scheduler.TestScheduler(t, conn, wrapper)
		repo, err := NewRepository(rw, rw, kms, sche)
		assert.NoError(err)
		require.NotNil(repo)
		badId, err := newCredentialLibraryId()
		assert.NoError(err)
		require.NotNil(badId)
		// test
		got, err := repo.LookupCredentialLibrary(ctx, badId)
		assert.NoError(err)
		assert.Empty(got)
	})
}

func TestRepository_ListSSHCertificateCredentialLibraries_Limits(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	sche := scheduler.TestScheduler(t, conn, wrapper)

	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	cs := TestCredentialStores(t, conn, wrapper, prj.GetPublicId(), 1)[0]
	const count = 10
	libs := TestSSHCertificateCredentialLibraries(t, conn, wrapper, cs.GetPublicId(), count)

	tests := []struct {
		name     string
		repoOpts []Option
		listOpts []Option
		wantLen  int
	}{
		{
			name:    "with-no-limits",
			wantLen: count,
		},
		{
			name:     "with-repo-limit",
			repoOpts: []Option{WithLimit(3)},
			wantLen:  3,
		},
		{
			name:     "with-negative-repo-limit",
			repoOpts: []Option{WithLimit(-1)},
			wantLen:  count,
		},
		{
			name:     "with-list-limit",
			listOpts: []Option{WithLimit(3)},
			wantLen:  3,
		},
		{
			name:     "with-negative-list-limit",
			listOpts: []Option{WithLimit(-1)},
			wantLen:  count,
		},
		{
			name:     "with-repo-smaller-than-list-limit",
			repoOpts: []Option{WithLimit(2)},
			listOpts: []Option{WithLimit(6)},
			wantLen:  6,
		},
		{
			name:     "with-repo-larger-than-list-limit",
			repoOpts: []Option{WithLimit(6)},
			listOpts: []Option{WithLimit(2)},
			wantLen:  2,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			ctx := context.Background()
			kms := kms.TestKms(t, conn, wrapper)
			repo, err := NewRepository(rw, rw, kms, sche, tt.repoOpts...)
			assert.NoError(err)
			require.NotNil(repo)
			got, err := repo.ListSSHCertificateCredentialLibraries(ctx, libs[0].StoreId, tt.listOpts...)
			require.NoError(err)
			assert.Len(got, tt.wantLen)
		})
	}
}

func TestRepository_UpdateSSHCertificateCredentialLibrary(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)

	changeVaultPath := func(p string) func(*SSHCertificateCredentialLibrary) *SSHCertificateCredentialLibrary {
		return func(l *SSHCertificateCredentialLibrary) *SSHCertificateCredentialLibrary {
			l.VaultPath = p
			return l
		}
	}

	changeName := func(n string) func(*SSHCertificateCredentialLibrary) *SSHCertificateCredentialLibrary {
		return func(l *SSHCertificateCredentialLibrary) *SSHCertificateCredentialLibrary {
			l.Name = n
			return l
		}
	}

	changeDescription := func(d string) func(*SSHCertificateCredentialLibrary) *SSHCertificateCredentialLibrary {
		return func(l *SSHCertificateCredentialLibrary) *SSHCertificateCredentialLibrary {
			l.Description = d
			return l
		}
	}

	changeUsername := func(s string) func(*SSHCertificateCredentialLibrary) *SSHCertificateCredentialLibrary {
		return func(l *SSHCertificateCredentialLibrary) *SSHCertificateCredentialLibrary {
			l.Username = s
			return l
		}
	}

	changeKeyType := func(s string) func(*SSHCertificateCredentialLibrary) *SSHCertificateCredentialLibrary {
		return func(l *SSHCertificateCredentialLibrary) *SSHCertificateCredentialLibrary {
			l.KeyType = s
			return l
		}
	}

	changeKeyBits := func(b uint32) func(*SSHCertificateCredentialLibrary) *SSHCertificateCredentialLibrary {
		return func(l *SSHCertificateCredentialLibrary) *SSHCertificateCredentialLibrary {
			l.KeyBits = b
			return l
		}
	}

	changeTtl := func(s string) func(*SSHCertificateCredentialLibrary) *SSHCertificateCredentialLibrary {
		return func(l *SSHCertificateCredentialLibrary) *SSHCertificateCredentialLibrary {
			l.Ttl = s
			return l
		}
	}

	changeKeyId := func(s string) func(*SSHCertificateCredentialLibrary) *SSHCertificateCredentialLibrary {
		return func(l *SSHCertificateCredentialLibrary) *SSHCertificateCredentialLibrary {
			l.KeyId = s
			return l
		}
	}

	changeCriticalOptions := func(s string) func(*SSHCertificateCredentialLibrary) *SSHCertificateCredentialLibrary {
		return func(l *SSHCertificateCredentialLibrary) *SSHCertificateCredentialLibrary {
			l.CriticalOptions = s
			return l
		}
	}

	changeExtensions := func(s string) func(*SSHCertificateCredentialLibrary) *SSHCertificateCredentialLibrary {
		return func(l *SSHCertificateCredentialLibrary) *SSHCertificateCredentialLibrary {
			l.Extensions = s
			return l
		}
	}

	makeNil := func() func(*SSHCertificateCredentialLibrary) *SSHCertificateCredentialLibrary {
		return func(l *SSHCertificateCredentialLibrary) *SSHCertificateCredentialLibrary {
			return nil
		}
	}

	makeEmbeddedNil := func() func(*SSHCertificateCredentialLibrary) *SSHCertificateCredentialLibrary {
		return func(l *SSHCertificateCredentialLibrary) *SSHCertificateCredentialLibrary {
			return &SSHCertificateCredentialLibrary{}
		}
	}

	deletePublicId := func() func(*SSHCertificateCredentialLibrary) *SSHCertificateCredentialLibrary {
		return func(l *SSHCertificateCredentialLibrary) *SSHCertificateCredentialLibrary {
			l.PublicId = ""
			return l
		}
	}

	nonExistentPublicId := func() func(*SSHCertificateCredentialLibrary) *SSHCertificateCredentialLibrary {
		return func(l *SSHCertificateCredentialLibrary) *SSHCertificateCredentialLibrary {
			l.PublicId = "abcd_OOOOOOOOOO"
			return l
		}
	}

	combine := func(fns ...func(l *SSHCertificateCredentialLibrary) *SSHCertificateCredentialLibrary) func(*SSHCertificateCredentialLibrary) *SSHCertificateCredentialLibrary {
		return func(l *SSHCertificateCredentialLibrary) *SSHCertificateCredentialLibrary {
			for _, fn := range fns {
				l = fn(l)
			}
			return l
		}
	}

	tests := []struct {
		name      string
		orig      *SSHCertificateCredentialLibrary
		chgFn     func(*SSHCertificateCredentialLibrary) *SSHCertificateCredentialLibrary
		masks     []string
		want      *SSHCertificateCredentialLibrary
		wantCount int
		wantErr   errors.Code
	}{
		{
			name: "nil-credential-library",
			orig: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					Username:  "name",
					VaultPath: "/some/path",
				},
			},
			chgFn:   makeNil(),
			masks:   []string{nameField, descriptionField},
			wantErr: errors.InvalidParameter,
		},
		{
			name: "nil-embedded-credential-library",
			orig: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					Username:  "name",
					VaultPath: "/some/path",
				},
			},
			chgFn:   makeEmbeddedNil(),
			masks:   []string{nameField, descriptionField},
			wantErr: errors.InvalidParameter,
		},
		{
			name: "no-public-id",
			orig: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					Username:  "name",
					VaultPath: "/some/path",
				},
			},
			chgFn:   deletePublicId(),
			masks:   []string{nameField, descriptionField},
			wantErr: errors.InvalidPublicId,
		},
		{
			name: "updating-non-existent-credential-library",
			orig: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					Username:  "name",
					VaultPath: "/some/path",
					Name:      "test-name-repo",
				},
			},
			chgFn:   combine(nonExistentPublicId(), changeName("test-update-name-repo")),
			masks:   []string{nameField},
			wantErr: errors.RecordNotFound,
		},
		{
			name: "empty-field-mask",
			orig: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					Username:  "name",
					VaultPath: "/some/path",
					Name:      "test-name-repo",
				},
			},
			chgFn:   changeName("test-update-name-repo"),
			wantErr: errors.EmptyFieldMask,
		},
		{
			name: "read-only-fields-in-field-mask",
			orig: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					Username:  "name",
					VaultPath: "/some/path",
					Name:      "test-name-repo",
				},
			},
			chgFn:   changeName("test-update-name-repo"),
			masks:   []string{"PublicId", "CreateTime", "UpdateTime", "StoreId"},
			wantErr: errors.InvalidFieldMask,
		},
		{
			name: "unknown-field-in-field-mask",
			orig: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					Username:  "name",
					VaultPath: "/some/path",
					Name:      "test-name-repo",
				},
			},
			chgFn:   changeName("test-update-name-repo"),
			masks:   []string{"Bilbo"},
			wantErr: errors.InvalidFieldMask,
		},
		{
			name: "change-name",
			orig: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					Username:  "name",
					VaultPath: "/some/path",
					Name:      "test-name-repo",
				},
			},
			chgFn: changeName("test-update-name-repo"),
			masks: []string{nameField},
			want: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					Username:  "name",
					VaultPath: "/some/path",
					Name:      "test-update-name-repo",
				},
			},
			wantCount: 1,
		},
		{
			name: "change-description",
			orig: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					Username:    "name",
					VaultPath:   "/some/path",
					Description: "test-description-repo",
				},
			},
			chgFn: changeDescription("test-update-description-repo"),
			masks: []string{descriptionField},
			want: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					Username:    "name",
					VaultPath:   "/some/path",
					Description: "test-update-description-repo",
				},
			},
			wantCount: 1,
		},
		{
			name: "change-name-and-description",
			orig: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					Username:    "name",
					VaultPath:   "/some/path",
					Name:        "test-name-repo",
					Description: "test-description-repo",
				},
			},
			chgFn: combine(changeDescription("test-update-description-repo"), changeName("test-update-name-repo")),
			masks: []string{nameField, descriptionField},
			want: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					Username:    "name",
					VaultPath:   "/some/path",
					Name:        "test-update-name-repo",
					Description: "test-update-description-repo",
				},
			},
			wantCount: 1,
		},
		{
			name: "change-username",
			orig: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					Username:  "name",
					VaultPath: "/some/path",
				},
			},
			chgFn: changeUsername("update-name"),
			masks: []string{usernameField},
			want: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					Username:  "update-name",
					VaultPath: "/some/path",
				},
			},
			wantCount: 1,
		},
		{
			name: "change-keytype",
			orig: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					KeyType:   KeyTypeEd25519,
					VaultPath: "/some/path",
					Username:  "name",
				},
			},
			chgFn: changeKeyType(KeyTypeEcdsa),
			masks: []string{keyTypeField},
			want: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					KeyType:   KeyTypeEcdsa,
					VaultPath: "/some/path",
					Username:  "name",
				},
			},
			wantCount: 1,
		},
		{
			name: "change-keybits",
			orig: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					KeyType:   KeyTypeEcdsa,
					KeyBits:   224,
					VaultPath: "/some/path",
					Username:  "name",
				},
			},
			chgFn: changeKeyBits(256),
			masks: []string{keyBitsField},
			want: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					KeyType:   KeyTypeEcdsa,
					KeyBits:   256,
					VaultPath: "/some/path",
					Username:  "name",
				},
			},
			wantCount: 1,
		},
		{
			name: "change-ttl",
			orig: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					Ttl:       "10s",
					VaultPath: "/some/path",
					Username:  "name",
				},
			},
			chgFn: changeTtl("1h"),
			masks: []string{ttlField},
			want: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					Ttl:       "1h",
					VaultPath: "/some/path",
					Username:  "name",
				},
			},
			wantCount: 1,
		},
		{
			name: "change-keyid",
			orig: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					KeyId:     "id",
					VaultPath: "/some/path",
					Username:  "name",
				},
			},
			chgFn: changeKeyId("update-id"),
			masks: []string{keyIdField},
			want: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					KeyId:     "update-id",
					VaultPath: "/some/path",
					Username:  "name",
				},
			},
			wantCount: 1,
		},
		{
			name: "change-critical-options",
			orig: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					CriticalOptions: "options",
					VaultPath:       "/some/path",
					Username:        "name",
				},
			},
			chgFn: changeCriticalOptions("update-options"),
			masks: []string{criticalOptionsField},
			want: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					CriticalOptions: "update-options",
					VaultPath:       "/some/path",
					Username:        "name",
				},
			},
			wantCount: 1,
		},
		{
			name: "change-extensions",
			orig: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					Extensions: "extensions",
					VaultPath:  "/some/path",
					Username:   "name",
				},
			},
			chgFn: changeExtensions("update-extensions"),
			masks: []string{extensionsField},
			want: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					Extensions: "update-extensions",
					VaultPath:  "/some/path",
					Username:   "name",
				},
			},
			wantCount: 1,
		},
		{
			name: "delete-name",
			orig: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					Username:    "name",
					VaultPath:   "/some/path",
					Name:        "test-name-repo",
					Description: "test-description-repo",
				},
			},
			masks: []string{nameField},
			chgFn: combine(changeDescription("test-update-description-repo"), changeName("")),
			want: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					Username:    "name",
					VaultPath:   "/some/path",
					Description: "test-description-repo",
				},
			},
			wantCount: 1,
		},
		{
			name: "delete-description",
			orig: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					Username:    "name",
					VaultPath:   "/some/path",
					Name:        "test-name-repo",
					Description: "test-description-repo",
				},
			},
			masks: []string{descriptionField},
			chgFn: combine(changeDescription(""), changeName("test-update-name-repo")),
			want: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					Username:  "name",
					VaultPath: "/some/path",
					Name:      "test-name-repo",
				},
			},
			wantCount: 1,
		},
		{
			name: "do-not-delete-name",
			orig: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					Username:    "name",
					VaultPath:   "/some/path",
					Name:        "test-name-repo",
					Description: "test-description-repo",
				},
			},
			masks: []string{descriptionField},
			chgFn: combine(changeDescription("test-update-description-repo"), changeName("")),
			want: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					Username:    "name",
					VaultPath:   "/some/path",
					Name:        "test-name-repo",
					Description: "test-update-description-repo",
				},
			},
			wantCount: 1,
		},
		{
			name: "do-not-delete-description",
			orig: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					Username:    "name",
					VaultPath:   "/some/path",
					Name:        "test-name-repo",
					Description: "test-description-repo",
				},
			},
			masks: []string{nameField},
			chgFn: combine(changeDescription(""), changeName("test-update-name-repo")),
			want: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					Username:    "name",
					VaultPath:   "/some/path",
					Name:        "test-update-name-repo",
					Description: "test-description-repo",
				},
			},
			wantCount: 1,
		},
		{
			name: "change-vault-path",
			orig: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					Username:  "name",
					VaultPath: "/old/path",
				},
			},
			chgFn: changeVaultPath("/new/path"),
			masks: []string{vaultPathField},
			want: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					Username:  "name",
					VaultPath: "/new/path",
				},
			},
			wantCount: 1,
		},
		{
			name: "delete-vault-path",
			orig: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					Username:  "name",
					VaultPath: "/some/path",
				},
			},
			chgFn:   changeVaultPath(""),
			masks:   []string{vaultPathField},
			wantErr: errors.NotNull,
		},
		{
			name: "change-key-type-invalid",
			orig: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					Username:  "name",
					VaultPath: "/some/path",
					KeyType:   KeyTypeEcdsa,
					KeyBits:   256,
				},
			},
			chgFn:   changeKeyType(KeyTypeEd25519),
			masks:   []string{keyTypeField},
			wantErr: errors.NotSpecificIntegrity,
		},
		{
			name: "change-key-type-bits-valid",
			orig: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					Username:  "name",
					VaultPath: "/some/path",
					KeyType:   KeyTypeEcdsa,
					KeyBits:   256,
				},
			},
			chgFn: combine(changeKeyType(KeyTypeRsa), changeKeyBits(2048)),
			masks: []string{keyTypeField, keyBitsField},
			want: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					Username:  "name",
					VaultPath: "/some/path",
					KeyType:   KeyTypeRsa,
					KeyBits:   2048,
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
			sche := scheduler.TestScheduler(t, conn, wrapper)
			repo, err := NewRepository(rw, rw, kms, sche)
			assert.NoError(err)
			require.NotNil(repo)

			_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
			cs := TestCredentialStores(t, conn, wrapper, prj.GetPublicId(), 1)[0]

			tt.orig.StoreId = cs.GetPublicId()
			orig, err := repo.CreateSSHCertificateCredentialLibrary(ctx, prj.GetPublicId(), tt.orig)
			assert.NoError(err)
			require.NotNil(orig)

			if tt.chgFn != nil {
				orig = tt.chgFn(orig)
			}
			got, gotCount, err := repo.UpdateSSHCertificateCredentialLibrary(ctx, prj.GetPublicId(), orig, 1, tt.masks)
			if tt.wantErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantErr), err), "want err: %q got: %q", tt.wantErr, err)
				assert.Equal(tt.wantCount, gotCount, "row count")
				assert.Nil(got)
				return
			}
			require.NoError(err)
			assert.Empty(tt.orig.PublicId)
			require.NotNil(got)
			assertPublicId(t, SSHCertificateCredentialLibraryPrefix, got.GetPublicId())
			assert.Equal(tt.wantCount, gotCount, "row count")
			assert.NotSame(tt.orig, got)
			assert.Equal(tt.orig.StoreId, got.StoreId)
			underlyingDB, err := conn.SqlDB(ctx)
			require.NoError(err)
			dbassert := dbassert.New(t, underlyingDB)

			switch tt.want.Name {
			case "":
				dbassert.IsNull(got, "name")
			default:
				assert.Equal(tt.want.Name, got.Name)
			}

			switch tt.want.Description {
			case "":
				dbassert.IsNull(got, "description")
			default:
				assert.Equal(tt.want.Description, got.Description)
			}

			switch tt.want.Username {
			case "":
				dbassert.IsNull(got, "Username")
			default:
				assert.Equal(tt.want.Username, got.Username)
			}

			switch tt.want.KeyType {
			case "":
				assert.Equal(got.KeyType, KeyTypeEd25519)
			default:
				assert.Equal(tt.want.KeyType, got.KeyType)
			}

			switch tt.want.KeyBits {
			case (0):
				assert.Zero(got.KeyBits)
			default:
				assert.Equal(tt.want.KeyBits, got.KeyBits)
			}

			switch tt.want.Ttl {
			case "":
				dbassert.IsNull(got, "Ttl")
			default:
				assert.Equal(tt.want.Ttl, got.Ttl)
			}

			switch tt.want.KeyId {
			case "":
				dbassert.IsNull(got, "KeyId")
			default:
				assert.Equal(tt.want.KeyId, got.KeyId)
			}

			switch tt.want.CriticalOptions {
			case "":
				dbassert.IsNull(got, "CriticalOptions")
			default:
				assert.Equal(tt.want.CriticalOptions, got.CriticalOptions)
			}

			switch tt.want.Extensions {
			case "":
				dbassert.IsNull(got, "Extensions")
			default:
				assert.Equal(tt.want.Extensions, got.Extensions)
			}

			if tt.wantCount > 0 {
				assert.NoError(db.TestVerifyOplog(t, rw, got.GetPublicId(), db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second)))
			}
		})
	}

	t.Run("invalid-duplicate-names", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		ctx := context.Background()
		kms := kms.TestKms(t, conn, wrapper)
		sche := scheduler.TestScheduler(t, conn, wrapper)
		repo, err := NewRepository(rw, rw, kms, sche)
		assert.NoError(err)
		require.NotNil(repo)

		name := "test-dup-name"
		_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		cs := TestCredentialStores(t, conn, wrapper, prj.GetPublicId(), 1)[0]
		libs := TestSSHCertificateCredentialLibraries(t, conn, wrapper, cs.GetPublicId(), 2)

		lA, lB := libs[0], libs[1]

		lA.Name = name
		got1, gotCount1, err := repo.UpdateSSHCertificateCredentialLibrary(ctx, prj.GetPublicId(), lA, 1, []string{"name"})
		assert.NoError(err)
		require.NotNil(got1)
		assert.Equal(name, got1.Name)
		assert.Equal(1, gotCount1, "row count")
		assert.NoError(db.TestVerifyOplog(t, rw, lA.GetPublicId(), db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second)))

		lB.Name = name
		got2, gotCount2, err := repo.UpdateSSHCertificateCredentialLibrary(ctx, prj.GetPublicId(), lB, 1, []string{"name"})
		assert.Truef(errors.Match(errors.T(errors.NotUnique), err), "want err code: %v got err: %v", errors.NotUnique, err)
		assert.Nil(got2)
		assert.Equal(db.NoRowsAffected, gotCount2, "row count")
		err = db.TestVerifyOplog(t, rw, lB.GetPublicId(), db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second))
		assert.Error(err)
		assert.True(errors.IsNotFoundError(err))
	})

	t.Run("valid-duplicate-names-diff-CredentialStores", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		ctx := context.Background()
		kms := kms.TestKms(t, conn, wrapper)
		sche := scheduler.TestScheduler(t, conn, wrapper)
		repo, err := NewRepository(rw, rw, kms, sche)
		assert.NoError(err)
		require.NotNil(repo)

		_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		css := TestCredentialStores(t, conn, wrapper, prj.GetPublicId(), 2)

		csA, csB := css[0], css[1]

		in := &SSHCertificateCredentialLibrary{
			SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
				Username:  "name",
				VaultPath: "/some/path",
				Name:      "test-name-repo",
			},
		}
		in2 := in.clone()

		in.StoreId = csA.GetPublicId()
		got, err := repo.CreateSSHCertificateCredentialLibrary(ctx, prj.GetPublicId(), in)
		assert.NoError(err)
		require.NotNil(got)
		assertPublicId(t, SSHCertificateCredentialLibraryPrefix, got.GetPublicId())
		assert.NotSame(in, got)
		assert.Equal(in.Name, got.Name)
		assert.Equal(in.Description, got.Description)

		in2.StoreId = csB.GetPublicId()
		in2.Name = "first-name"
		got2, err := repo.CreateSSHCertificateCredentialLibrary(ctx, prj.GetPublicId(), in2)
		assert.NoError(err)
		require.NotNil(got2)
		got2.Name = got.Name
		got3, gotCount3, err := repo.UpdateSSHCertificateCredentialLibrary(ctx, prj.GetPublicId(), got2, 1, []string{"name"})
		assert.NoError(err)
		require.NotNil(got3)
		assert.NotSame(got2, got3)
		assert.Equal(got.Name, got3.Name)
		assert.Equal(got2.Description, got3.Description)
		assert.Equal(1, gotCount3, "row count")
		assert.NoError(db.TestVerifyOplog(t, rw, got2.GetPublicId(), db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second)))
	})

	t.Run("valid-update-with-expired-store-token", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		ctx := context.Background()
		kms := kms.TestKms(t, conn, wrapper)
		sche := scheduler.TestScheduler(t, conn, wrapper)
		repo, err := NewRepository(rw, rw, kms, sche)
		assert.NoError(err)
		require.NotNil(repo)

		_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		css := TestCredentialStores(t, conn, wrapper, prj.GetPublicId(), 1)
		cs := css[0]

		in := &SSHCertificateCredentialLibrary{
			SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
				Username:  "name",
				VaultPath: "/some/path",
				Name:      "test-name-repo",
			},
		}

		in.StoreId = cs.GetPublicId()
		got, err := repo.CreateSSHCertificateCredentialLibrary(ctx, prj.GetPublicId(), in)
		assert.NoError(err)
		require.NotNil(got)

		// Expire the credential store Vault token
		rows, err := rw.Exec(context.Background(),
			"update credential_vault_token set status = ? where token_hmac = ?",
			[]any{ExpiredToken, cs.Token().TokenHmac})
		require.NoError(err)
		require.Equal(1, rows)

		got.Name = "new-name"
		updated, gotCount, err := repo.UpdateSSHCertificateCredentialLibrary(ctx, prj.GetPublicId(), got, 1, []string{"name"})
		assert.NoError(err)
		require.NotNil(updated)
		assert.Equal("new-name", updated.Name)
		assert.Equal(1, gotCount)
	})

	t.Run("change-project-id", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		ctx := context.Background()
		kms := kms.TestKms(t, conn, wrapper)
		sche := scheduler.TestScheduler(t, conn, wrapper)
		repo, err := NewRepository(rw, rw, kms, sche)
		assert.NoError(err)
		require.NotNil(repo)

		_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		css := TestCredentialStores(t, conn, wrapper, prj.GetPublicId(), 2)

		csA, csB := css[0], css[1]

		lA := TestSSHCertificateCredentialLibraries(t, conn, wrapper, csA.GetPublicId(), 1)[0]
		lB := TestSSHCertificateCredentialLibraries(t, conn, wrapper, csB.GetPublicId(), 1)[0]

		assert.NotEqual(lA.StoreId, lB.StoreId)
		orig := lA.clone()

		lA.StoreId = lB.StoreId
		assert.Equal(lA.StoreId, lB.StoreId)

		got1, gotCount1, err := repo.UpdateSSHCertificateCredentialLibrary(ctx, prj.GetPublicId(), lA, 1, []string{"name"})

		assert.NoError(err)
		require.NotNil(got1)
		assert.Equal(orig.StoreId, got1.StoreId)
		assert.Equal(1, gotCount1, "row count")
		assert.NoError(db.TestVerifyOplog(t, rw, lA.GetPublicId(), db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second)))
	})

	t.Run("change-key-type-bits-consecutive", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		ctx := context.Background()
		kms := kms.TestKms(t, conn, wrapper)
		sche := scheduler.TestScheduler(t, conn, wrapper)
		repo, err := NewRepository(rw, rw, kms, sche)
		assert.NoError(err)
		require.NotNil(repo)

		_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		cs := TestCredentialStores(t, conn, wrapper, prj.GetPublicId(), 1)[0]

		in := &SSHCertificateCredentialLibrary{
			SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
				Username:  "name",
				VaultPath: "/some/path",
				KeyType:   KeyTypeEcdsa,
				KeyBits:   521,
			},
		}
		in.StoreId = cs.GetPublicId()

		orig, err := repo.CreateSSHCertificateCredentialLibrary(ctx, prj.GetPublicId(), in)
		assert.NoError(err)
		require.NotNil(orig)

		orig.KeyBits = 0

		got, gotCount, err := repo.UpdateSSHCertificateCredentialLibrary(ctx, prj.GetPublicId(), orig, 1, []string{keyBitsField})
		require.NoError(err)
		assert.Empty(in.PublicId)
		require.NotNil(got)
		assertPublicId(t, SSHCertificateCredentialLibraryPrefix, got.GetPublicId())
		assert.Equal(1, gotCount, "row count")
		assert.NotSame(orig, got)
		assert.Equal(orig.StoreId, got.StoreId)

		orig.KeyType = KeyTypeRsa

		got, gotCount, err = repo.UpdateSSHCertificateCredentialLibrary(ctx, prj.GetPublicId(), orig, 2, []string{keyTypeField})
		require.NoError(err)
		require.NotNil(got)
		assertPublicId(t, SSHCertificateCredentialLibraryPrefix, got.GetPublicId())
		assert.Equal(1, gotCount, "row count")
		assert.NotSame(orig, got)
		assert.Equal(orig.StoreId, got.StoreId)

		orig.KeyBits = 3072

		got, gotCount, err = repo.UpdateSSHCertificateCredentialLibrary(ctx, prj.GetPublicId(), orig, 3, []string{keyTypeField})
		require.NoError(err)
		require.NotNil(got)
		assertPublicId(t, SSHCertificateCredentialLibraryPrefix, got.GetPublicId())
		assert.Equal(1, gotCount, "row count")
		assert.NotSame(orig, got)
		assert.Equal(orig.StoreId, got.StoreId)

		assert.Equal(KeyTypeRsa, orig.KeyType)
		assert.Equal(uint32(3072), orig.KeyBits)
	})
}

func TestRepository_DeleteSSHCertificateCredentialLibrary(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)

	{
		_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		cs := TestCredentialStores(t, conn, wrapper, prj.GetPublicId(), 1)[0]
		l := TestSSHCertificateCredentialLibraries(t, conn, wrapper, cs.GetPublicId(), 1)[0]

		badId, err := newSSHCertificateCredentialLibraryId()
		require.NoError(t, err)
		require.NotNil(t, badId)

		tests := []struct {
			name    string
			in      string
			want    int
			wantErr errors.Code
		}{
			{
				name: "found",
				in:   l.GetPublicId(),
				want: 1,
			},
			{
				name: "not-found",
				in:   badId,
			},
			{
				name:    "empty-public-id",
				in:      "",
				wantErr: errors.InvalidParameter,
			},
		}

		for _, tt := range tests {
			tt := tt
			t.Run(tt.name, func(t *testing.T) {
				assert, require := assert.New(t), require.New(t)
				ctx := context.Background()
				kms := kms.TestKms(t, conn, wrapper)
				sche := scheduler.TestScheduler(t, conn, wrapper)
				repo, err := NewRepository(rw, rw, kms, sche)
				assert.NoError(err)
				require.NotNil(repo)

				got, err := repo.DeleteSSHCertificateCredentialLibrary(ctx, prj.GetPublicId(), tt.in)
				if tt.wantErr != 0 {
					assert.Truef(errors.Match(errors.T(tt.wantErr), err), "want err: %q got: %q", tt.wantErr, err)
					return
				}
				assert.NoError(err)
				assert.Equal(tt.want, got, "row count")

				cl, err := repo.LookupSSHCertificateCredentialLibrary(ctx, tt.in)
				assert.Empty(err)
				assert.Empty(cl)
			})
		}
	}
}
