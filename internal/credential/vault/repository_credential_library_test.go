// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"context"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/credential/vault/store"
	"github.com/hashicorp/boundary/internal/db"
	dbassert "github.com/hashicorp/boundary/internal/db/assert"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/scheduler"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestRepository_CreateCredentialLibrary(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)

	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	cs := TestCredentialStores(t, conn, wrapper, prj.GetPublicId(), 1)[0]

	tests := []struct {
		name    string
		in      *CredentialLibrary
		opts    []Option
		want    *CredentialLibrary
		wantErr errors.Code
	}{
		{
			name:    "nil-CredentialLibrary",
			wantErr: errors.InvalidParameter,
		},
		{
			name:    "nil-embedded-CredentialLibrary",
			in:      &CredentialLibrary{},
			wantErr: errors.InvalidParameter,
		},
		{
			name: "invalid-no-store-id",
			in: &CredentialLibrary{
				CredentialLibrary: &store.CredentialLibrary{},
			},
			wantErr: errors.InvalidParameter,
		},
		{
			name: "invalid-public-id-set",
			in: &CredentialLibrary{
				CredentialLibrary: &store.CredentialLibrary{
					StoreId:  cs.GetPublicId(),
					PublicId: "abcd_OOOOOOOOOO",
				},
			},
			wantErr: errors.InvalidParameter,
		},
		{
			name: "invalid-no-vault-path",
			in: &CredentialLibrary{
				CredentialLibrary: &store.CredentialLibrary{
					StoreId: cs.GetPublicId(),
				},
			},
			wantErr: errors.InvalidParameter,
		},
		{
			name: "valid-no-options",
			in: &CredentialLibrary{
				CredentialLibrary: &store.CredentialLibrary{
					StoreId:    cs.GetPublicId(),
					HttpMethod: "GET",
					VaultPath:  "/some/path",
				},
			},
			want: &CredentialLibrary{
				CredentialLibrary: &store.CredentialLibrary{
					StoreId:    cs.GetPublicId(),
					HttpMethod: "GET",
					VaultPath:  "/some/path",
				},
			},
		},
		{
			name: "valid-with-name",
			in: &CredentialLibrary{
				CredentialLibrary: &store.CredentialLibrary{
					StoreId:    cs.GetPublicId(),
					HttpMethod: "GET",
					Name:       "test-name-repo",
					VaultPath:  "/some/path",
				},
			},
			want: &CredentialLibrary{
				CredentialLibrary: &store.CredentialLibrary{
					StoreId:    cs.GetPublicId(),
					HttpMethod: "GET",
					Name:       "test-name-repo",
					VaultPath:  "/some/path",
				},
			},
		},
		{
			name: "valid-with-description",
			in: &CredentialLibrary{
				CredentialLibrary: &store.CredentialLibrary{
					StoreId:     cs.GetPublicId(),
					HttpMethod:  "GET",
					Description: "test-description-repo",
					VaultPath:   "/some/path",
				},
			},
			want: &CredentialLibrary{
				CredentialLibrary: &store.CredentialLibrary{
					StoreId:     cs.GetPublicId(),
					HttpMethod:  "GET",
					Description: "test-description-repo",
					VaultPath:   "/some/path",
				},
			},
		},
		{
			name: "valid-POST-method",
			in: &CredentialLibrary{
				CredentialLibrary: &store.CredentialLibrary{
					StoreId:     cs.GetPublicId(),
					HttpMethod:  "POST",
					Description: "test-description-repo",
					VaultPath:   "/some/path",
				},
			},
			want: &CredentialLibrary{
				CredentialLibrary: &store.CredentialLibrary{
					StoreId:     cs.GetPublicId(),
					HttpMethod:  "POST",
					Description: "test-description-repo",
					VaultPath:   "/some/path",
				},
			},
		},
		{
			name: "valid-POST-http-body",
			in: &CredentialLibrary{
				CredentialLibrary: &store.CredentialLibrary{
					StoreId:         cs.GetPublicId(),
					HttpMethod:      "POST",
					Description:     "test-description-repo",
					VaultPath:       "/some/path",
					HttpRequestBody: []byte(`{"common_name":"boundary.com"}`),
				},
			},
			want: &CredentialLibrary{
				CredentialLibrary: &store.CredentialLibrary{
					StoreId:         cs.GetPublicId(),
					HttpMethod:      "POST",
					Description:     "test-description-repo",
					VaultPath:       "/some/path",
					HttpRequestBody: []byte(`{"common_name":"boundary.com"}`),
				},
			},
		},
		{
			name: "valid-username-password-credential-type",
			in: &CredentialLibrary{
				CredentialLibrary: &store.CredentialLibrary{
					StoreId:        cs.GetPublicId(),
					HttpMethod:     "GET",
					VaultPath:      "/some/path",
					CredentialType: string(globals.UsernamePasswordCredentialType),
				},
			},
			want: &CredentialLibrary{
				CredentialLibrary: &store.CredentialLibrary{
					StoreId:        cs.GetPublicId(),
					HttpMethod:     "GET",
					VaultPath:      "/some/path",
					CredentialType: string(globals.UsernamePasswordCredentialType),
				},
			},
		},
		{
			name: "unknown-mapping-override-type",
			in: &CredentialLibrary{
				MappingOverride: unknownMapper(1),
				CredentialLibrary: &store.CredentialLibrary{
					StoreId:        cs.GetPublicId(),
					HttpMethod:     "GET",
					VaultPath:      "/some/path",
					CredentialType: string(globals.UsernamePasswordCredentialType),
				},
			},
			wantErr: errors.VaultInvalidMappingOverride,
		},
		{
			name: "invalid-mapping-override-type",
			in: &CredentialLibrary{
				MappingOverride: NewUsernamePasswordOverride(WithOverrideUsernameAttribute("test")),
				CredentialLibrary: &store.CredentialLibrary{
					StoreId:    cs.GetPublicId(),
					HttpMethod: "GET",
					VaultPath:  "/some/path",
				},
			},
			wantErr: errors.VaultInvalidMappingOverride,
		},
		{
			name: "valid-username-password-credential-type-with-username-override",
			in: &CredentialLibrary{
				MappingOverride: NewUsernamePasswordOverride(
					WithOverrideUsernameAttribute("utest"),
				),
				CredentialLibrary: &store.CredentialLibrary{
					StoreId:        cs.GetPublicId(),
					HttpMethod:     "GET",
					VaultPath:      "/some/path",
					CredentialType: string(globals.UsernamePasswordCredentialType),
				},
			},
			want: &CredentialLibrary{
				MappingOverride: NewUsernamePasswordOverride(
					WithOverrideUsernameAttribute("utest"),
				),
				CredentialLibrary: &store.CredentialLibrary{
					StoreId:        cs.GetPublicId(),
					HttpMethod:     "GET",
					VaultPath:      "/some/path",
					CredentialType: string(globals.UsernamePasswordCredentialType),
				},
			},
		},
		{
			name: "valid-username-password-credential-type-with-password-override",
			in: &CredentialLibrary{
				MappingOverride: NewUsernamePasswordOverride(
					WithOverridePasswordAttribute("ptest"),
				),
				CredentialLibrary: &store.CredentialLibrary{
					StoreId:        cs.GetPublicId(),
					HttpMethod:     "GET",
					VaultPath:      "/some/path",
					CredentialType: string(globals.UsernamePasswordCredentialType),
				},
			},
			want: &CredentialLibrary{
				MappingOverride: NewUsernamePasswordOverride(
					WithOverridePasswordAttribute("ptest"),
				),
				CredentialLibrary: &store.CredentialLibrary{
					StoreId:        cs.GetPublicId(),
					HttpMethod:     "GET",
					VaultPath:      "/some/path",
					CredentialType: string(globals.UsernamePasswordCredentialType),
				},
			},
		},
		{
			name: "valid-username-password-credential-type-with-username-and-password-override",
			in: &CredentialLibrary{
				MappingOverride: NewUsernamePasswordOverride(
					WithOverrideUsernameAttribute("utest"),
					WithOverridePasswordAttribute("ptest"),
				),
				CredentialLibrary: &store.CredentialLibrary{
					StoreId:        cs.GetPublicId(),
					HttpMethod:     "GET",
					VaultPath:      "/some/path",
					CredentialType: string(globals.UsernamePasswordCredentialType),
				},
			},
			want: &CredentialLibrary{
				MappingOverride: NewUsernamePasswordOverride(
					WithOverrideUsernameAttribute("utest"),
					WithOverridePasswordAttribute("ptest"),
				),
				CredentialLibrary: &store.CredentialLibrary{
					StoreId:        cs.GetPublicId(),
					HttpMethod:     "GET",
					VaultPath:      "/some/path",
					CredentialType: string(globals.UsernamePasswordCredentialType),
				},
			},
		},
		{
			name: "valid-password-credential-type",
			in: &CredentialLibrary{
				CredentialLibrary: &store.CredentialLibrary{
					StoreId:        cs.GetPublicId(),
					HttpMethod:     "GET",
					VaultPath:      "/some/path",
					CredentialType: string(globals.PasswordCredentialType),
				},
			},
			want: &CredentialLibrary{
				CredentialLibrary: &store.CredentialLibrary{
					StoreId:        cs.GetPublicId(),
					HttpMethod:     "GET",
					VaultPath:      "/some/path",
					CredentialType: string(globals.PasswordCredentialType),
				},
			},
		},
		{
			name: "unknown-password-mapping-override-type",
			in: &CredentialLibrary{
				MappingOverride: unknownMapper(1),
				CredentialLibrary: &store.CredentialLibrary{
					StoreId:        cs.GetPublicId(),
					HttpMethod:     "GET",
					VaultPath:      "/some/path",
					CredentialType: string(globals.PasswordCredentialType),
				},
			},
			wantErr: errors.VaultInvalidMappingOverride,
		},
		{
			name: "invalid-password-mapping-override-type",
			in: &CredentialLibrary{
				MappingOverride: NewUsernamePasswordOverride(WithOverrideUsernameAttribute("test")),
				CredentialLibrary: &store.CredentialLibrary{
					StoreId:        cs.GetPublicId(),
					HttpMethod:     "GET",
					VaultPath:      "/some/path",
					CredentialType: string(globals.PasswordCredentialType),
				},
			},
			wantErr: errors.VaultInvalidMappingOverride,
		},
		{
			name: "valid-password-credential-type-with-password-override",
			in: &CredentialLibrary{
				MappingOverride: NewPasswordOverride(
					WithOverridePasswordAttribute("ptest"),
				),
				CredentialLibrary: &store.CredentialLibrary{
					StoreId:        cs.GetPublicId(),
					HttpMethod:     "GET",
					VaultPath:      "/some/path",
					CredentialType: string(globals.PasswordCredentialType),
				},
			},
			want: &CredentialLibrary{
				MappingOverride: NewPasswordOverride(
					WithOverridePasswordAttribute("ptest"),
				),
				CredentialLibrary: &store.CredentialLibrary{
					StoreId:        cs.GetPublicId(),
					HttpMethod:     "GET",
					VaultPath:      "/some/path",
					CredentialType: string(globals.PasswordCredentialType),
				},
			},
		},
		{
			name: "valid-ssh-private-key-credential-type",
			in: &CredentialLibrary{
				CredentialLibrary: &store.CredentialLibrary{
					StoreId:        cs.GetPublicId(),
					HttpMethod:     "GET",
					VaultPath:      "/some/path",
					CredentialType: string(globals.SshPrivateKeyCredentialType),
				},
			},
			want: &CredentialLibrary{
				CredentialLibrary: &store.CredentialLibrary{
					StoreId:        cs.GetPublicId(),
					HttpMethod:     "GET",
					VaultPath:      "/some/path",
					CredentialType: string(globals.SshPrivateKeyCredentialType),
				},
			},
		},
		{
			name: "unknown-ssh-private-key-mapping-override-type",
			in: &CredentialLibrary{
				MappingOverride: unknownMapper(1),
				CredentialLibrary: &store.CredentialLibrary{
					StoreId:        cs.GetPublicId(),
					HttpMethod:     "GET",
					VaultPath:      "/some/path",
					CredentialType: string(globals.SshPrivateKeyCredentialType),
				},
			},
			wantErr: errors.VaultInvalidMappingOverride,
		},
		{
			name: "invalid-ssh-private-key-mapping-override-type",
			in: &CredentialLibrary{
				MappingOverride: NewUsernamePasswordOverride(WithOverrideUsernameAttribute("test")),
				CredentialLibrary: &store.CredentialLibrary{
					StoreId:        cs.GetPublicId(),
					HttpMethod:     "GET",
					VaultPath:      "/some/path",
					CredentialType: string(globals.SshPrivateKeyCredentialType),
				},
			},
			wantErr: errors.VaultInvalidMappingOverride,
		},
		{
			name: "valid-ssh-private-key-credential-type-with-username-override",
			in: &CredentialLibrary{
				MappingOverride: NewSshPrivateKeyOverride(
					WithOverrideUsernameAttribute("utest"),
				),
				CredentialLibrary: &store.CredentialLibrary{
					StoreId:        cs.GetPublicId(),
					HttpMethod:     "GET",
					VaultPath:      "/some/path",
					CredentialType: string(globals.SshPrivateKeyCredentialType),
				},
			},
			want: &CredentialLibrary{
				MappingOverride: NewSshPrivateKeyOverride(
					WithOverrideUsernameAttribute("utest"),
				),
				CredentialLibrary: &store.CredentialLibrary{
					StoreId:        cs.GetPublicId(),
					HttpMethod:     "GET",
					VaultPath:      "/some/path",
					CredentialType: string(globals.SshPrivateKeyCredentialType),
				},
			},
		},
		{
			name: "valid-ssh-private-key-credential-type-with-private-key-override",
			in: &CredentialLibrary{
				MappingOverride: NewSshPrivateKeyOverride(
					WithOverridePrivateKeyAttribute("ptest"),
				),
				CredentialLibrary: &store.CredentialLibrary{
					StoreId:        cs.GetPublicId(),
					HttpMethod:     "GET",
					VaultPath:      "/some/path",
					CredentialType: string(globals.SshPrivateKeyCredentialType),
				},
			},
			want: &CredentialLibrary{
				MappingOverride: NewSshPrivateKeyOverride(
					WithOverridePrivateKeyAttribute("ptest"),
				),
				CredentialLibrary: &store.CredentialLibrary{
					StoreId:        cs.GetPublicId(),
					HttpMethod:     "GET",
					VaultPath:      "/some/path",
					CredentialType: string(globals.SshPrivateKeyCredentialType),
				},
			},
		},
		{
			name: "valid-ssh-private-key-credential-type-with-passphrase-override",
			in: &CredentialLibrary{
				MappingOverride: NewSshPrivateKeyOverride(
					WithOverridePrivateKeyPassphraseAttribute("passtest"),
				),
				CredentialLibrary: &store.CredentialLibrary{
					StoreId:        cs.GetPublicId(),
					HttpMethod:     "GET",
					VaultPath:      "/some/path",
					CredentialType: string(globals.SshPrivateKeyCredentialType),
				},
			},
			want: &CredentialLibrary{
				MappingOverride: NewSshPrivateKeyOverride(
					WithOverridePrivateKeyPassphraseAttribute("passtest"),
				),
				CredentialLibrary: &store.CredentialLibrary{
					StoreId:        cs.GetPublicId(),
					HttpMethod:     "GET",
					VaultPath:      "/some/path",
					CredentialType: string(globals.SshPrivateKeyCredentialType),
				},
			},
		},
		{
			name: "valid-ssh-private-keyt-credential-type-with-all-override",
			in: &CredentialLibrary{
				MappingOverride: NewSshPrivateKeyOverride(
					WithOverrideUsernameAttribute("utest"),
					WithOverridePrivateKeyAttribute("pktest"),
					WithOverridePrivateKeyPassphraseAttribute("ptest"),
				),
				CredentialLibrary: &store.CredentialLibrary{
					StoreId:        cs.GetPublicId(),
					HttpMethod:     "GET",
					VaultPath:      "/some/path",
					CredentialType: string(globals.SshPrivateKeyCredentialType),
				},
			},
			want: &CredentialLibrary{
				MappingOverride: NewSshPrivateKeyOverride(
					WithOverrideUsernameAttribute("utest"),
					WithOverridePrivateKeyAttribute("pktest"),
					WithOverridePrivateKeyPassphraseAttribute("ptest"),
				),
				CredentialLibrary: &store.CredentialLibrary{
					StoreId:        cs.GetPublicId(),
					HttpMethod:     "GET",
					VaultPath:      "/some/path",
					CredentialType: string(globals.SshPrivateKeyCredentialType),
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
			repo, err := NewRepository(ctx, rw, rw, kms, sche)
			require.NoError(err)
			require.NotNil(repo)
			got, err := repo.CreateCredentialLibrary(ctx, prj.GetPublicId(), tt.in, tt.opts...)
			if tt.wantErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantErr), err), "want err: %q got: %q", tt.wantErr, err)
				assert.Nil(got)
				return
			}
			require.NoError(err)
			assert.Empty(tt.in.PublicId)
			require.NotNil(got)
			assertPublicId(t, globals.VaultCredentialLibraryPrefix, got.GetPublicId())
			assert.NotSame(tt.in, got)
			assert.Equal(tt.want.Name, got.Name)
			assert.Equal(tt.want.Description, got.Description)
			assert.Equal(tt.want.CredentialType(), got.CredentialType())
			assert.Equal(got.CreateTime, got.UpdateTime)

			assert.NoError(db.TestVerifyOplog(t, rw, got.GetPublicId(), db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second)))

			if tt.in.MappingOverride != nil {
				require.NotNil(got.MappingOverride)
				assert.IsType(tt.want.MappingOverride, got.MappingOverride)
				switch w := tt.want.MappingOverride.(type) {
				case *UsernamePasswordOverride:
					g, ok := got.MappingOverride.(*UsernamePasswordOverride)
					require.True(ok)
					assert.Equal(w.UsernameAttribute, g.UsernameAttribute)
					assert.Equal(w.PasswordAttribute, g.PasswordAttribute)

					// verify it was persisted in the database
					override := allocUsernamePasswordOverride()
					assert.NoError(rw.LookupWhere(ctx, &override, "library_id = ?", []any{got.GetPublicId()}))

				case *PasswordOverride:
					g, ok := got.MappingOverride.(*PasswordOverride)
					require.True(ok)
					assert.Equal(w.PasswordAttribute, g.PasswordAttribute)

					// verify it was persisted in the database
					override := allocPasswordOverride()
					assert.NoError(rw.LookupWhere(ctx, &override, "library_id = ?", []any{got.GetPublicId()}))

				case *SshPrivateKeyOverride:
					g, ok := got.MappingOverride.(*SshPrivateKeyOverride)
					require.True(ok)
					assert.Equal(w.UsernameAttribute, g.UsernameAttribute)
					assert.Equal(w.PrivateKeyAttribute, g.PrivateKeyAttribute)
					assert.Equal(w.PrivateKeyPassphraseAttribute, g.PrivateKeyPassphraseAttribute)

					// verify it was persisted in the database
					override := allocSshPrivateKeyOverride()
					assert.NoError(rw.LookupWhere(ctx, &override, "library_id = ?", []any{got.GetPublicId()}))

				default:
					assert.Fail("Unknown mapping override")
				}
			}
		})
	}

	t.Run("invalid-duplicate-names", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		ctx := context.Background()
		kms := kms.TestKms(t, conn, wrapper)
		sche := scheduler.TestScheduler(t, conn, wrapper)
		repo, err := NewRepository(ctx, rw, rw, kms, sche)
		require.NoError(err)
		require.NotNil(repo)
		_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		cs := TestCredentialStores(t, conn, wrapper, prj.GetPublicId(), 1)[0]
		in := &CredentialLibrary{
			CredentialLibrary: &store.CredentialLibrary{
				StoreId:    cs.GetPublicId(),
				HttpMethod: "GET",
				VaultPath:  "/some/path",
				Name:       "test-name-repo",
			},
		}

		got, err := repo.CreateCredentialLibrary(ctx, prj.GetPublicId(), in)
		require.NoError(err)
		require.NotNil(got)
		assertPublicId(t, globals.VaultCredentialLibraryPrefix, got.GetPublicId())
		assert.NotSame(in, got)
		assert.Equal(in.Name, got.Name)
		assert.Equal(in.Description, got.Description)
		assert.Equal(got.CreateTime, got.UpdateTime)

		got2, err := repo.CreateCredentialLibrary(ctx, prj.GetPublicId(), in)
		assert.Truef(errors.Match(errors.T(errors.NotUnique), err), "want err: %q got: %q", errors.NotUnique, err)
		assert.Nil(got2)
	})

	t.Run("valid-duplicate-names-diff-stores", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		ctx := context.Background()
		kms := kms.TestKms(t, conn, wrapper)
		sche := scheduler.TestScheduler(t, conn, wrapper)
		repo, err := NewRepository(ctx, rw, rw, kms, sche)
		require.NoError(err)
		require.NotNil(repo)

		_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		css := TestCredentialStores(t, conn, wrapper, prj.GetPublicId(), 2)

		csA, csB := css[0], css[1]

		in := &CredentialLibrary{
			CredentialLibrary: &store.CredentialLibrary{
				HttpMethod: "GET",
				VaultPath:  "/some/path",
				Name:       "test-name-repo",
			},
		}
		in2 := in.clone()

		in.StoreId = csA.GetPublicId()
		got, err := repo.CreateCredentialLibrary(ctx, prj.GetPublicId(), in)
		require.NoError(err)
		require.NotNil(got)
		assertPublicId(t, globals.VaultCredentialLibraryPrefix, got.GetPublicId())
		assert.NotSame(in, got)
		assert.Equal(in.Name, got.Name)
		assert.Equal(in.Description, got.Description)
		assert.Equal(got.CreateTime, got.UpdateTime)

		in2.StoreId = csB.GetPublicId()
		got2, err := repo.CreateCredentialLibrary(ctx, prj.GetPublicId(), in2)
		require.NoError(err)
		require.NotNil(got2)
		assertPublicId(t, globals.VaultCredentialLibraryPrefix, got2.GetPublicId())
		assert.NotSame(in2, got2)
		assert.Equal(in2.Name, got2.Name)
		assert.Equal(in2.Description, got2.Description)
		assert.Equal(got2.CreateTime, got2.UpdateTime)
	})
}

func TestRepository_UpdateCredentialLibrary(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)

	changeHttpRequestBody := func(b []byte) func(*CredentialLibrary) *CredentialLibrary {
		return func(l *CredentialLibrary) *CredentialLibrary {
			l.HttpRequestBody = b
			return l
		}
	}

	changeHttpMethod := func(m Method) func(*CredentialLibrary) *CredentialLibrary {
		return func(l *CredentialLibrary) *CredentialLibrary {
			l.HttpMethod = string(m)
			return l
		}
	}

	makeHttpMethodEmptyString := func() func(*CredentialLibrary) *CredentialLibrary {
		return func(l *CredentialLibrary) *CredentialLibrary {
			l.HttpMethod = ""
			return l
		}
	}

	changeVaultPath := func(p string) func(*CredentialLibrary) *CredentialLibrary {
		return func(l *CredentialLibrary) *CredentialLibrary {
			l.VaultPath = p
			return l
		}
	}

	changeName := func(n string) func(*CredentialLibrary) *CredentialLibrary {
		return func(l *CredentialLibrary) *CredentialLibrary {
			l.Name = n
			return l
		}
	}

	changeDescription := func(d string) func(*CredentialLibrary) *CredentialLibrary {
		return func(l *CredentialLibrary) *CredentialLibrary {
			l.Description = d
			return l
		}
	}

	changeCredentialType := func(t globals.CredentialType) func(*CredentialLibrary) *CredentialLibrary {
		return func(l *CredentialLibrary) *CredentialLibrary {
			l.CredentialLibrary.CredentialType = string(t)
			return l
		}
	}

	changeMappingOverride := func(m MappingOverride) func(*CredentialLibrary) *CredentialLibrary {
		return func(l *CredentialLibrary) *CredentialLibrary {
			l.MappingOverride = m
			return l
		}
	}

	makeNil := func() func(*CredentialLibrary) *CredentialLibrary {
		return func(l *CredentialLibrary) *CredentialLibrary {
			return nil
		}
	}

	makeEmbeddedNil := func() func(*CredentialLibrary) *CredentialLibrary {
		return func(l *CredentialLibrary) *CredentialLibrary {
			return &CredentialLibrary{}
		}
	}

	deletePublicId := func() func(*CredentialLibrary) *CredentialLibrary {
		return func(l *CredentialLibrary) *CredentialLibrary {
			l.PublicId = ""
			return l
		}
	}

	nonExistentPublicId := func() func(*CredentialLibrary) *CredentialLibrary {
		return func(l *CredentialLibrary) *CredentialLibrary {
			l.PublicId = "abcd_OOOOOOOOOO"
			return l
		}
	}

	combine := func(fns ...func(l *CredentialLibrary) *CredentialLibrary) func(*CredentialLibrary) *CredentialLibrary {
		return func(l *CredentialLibrary) *CredentialLibrary {
			for _, fn := range fns {
				l = fn(l)
			}
			return l
		}
	}

	tests := []struct {
		name      string
		orig      *CredentialLibrary
		chgFn     func(*CredentialLibrary) *CredentialLibrary
		masks     []string
		want      *CredentialLibrary
		wantCount int
		wantErr   errors.Code
	}{
		{
			name: "nil-credential-library",
			orig: &CredentialLibrary{
				CredentialLibrary: &store.CredentialLibrary{
					HttpMethod: "GET",
					VaultPath:  "/some/path",
				},
			},
			chgFn:   makeNil(),
			masks:   []string{nameField, descriptionField},
			wantErr: errors.InvalidParameter,
		},
		{
			name: "nil-embedded-credential-library",
			orig: &CredentialLibrary{
				CredentialLibrary: &store.CredentialLibrary{
					HttpMethod: "GET",
					VaultPath:  "/some/path",
				},
			},
			chgFn:   makeEmbeddedNil(),
			masks:   []string{nameField, descriptionField},
			wantErr: errors.InvalidParameter,
		},
		{
			name: "no-public-id",
			orig: &CredentialLibrary{
				CredentialLibrary: &store.CredentialLibrary{
					HttpMethod: "GET",
					VaultPath:  "/some/path",
				},
			},
			chgFn:   deletePublicId(),
			masks:   []string{nameField, descriptionField},
			wantErr: errors.InvalidPublicId,
		},
		{
			name: "updating-non-existent-credential-library",
			orig: &CredentialLibrary{
				CredentialLibrary: &store.CredentialLibrary{
					HttpMethod: "GET",
					VaultPath:  "/some/path",
					Name:       "test-name-repo",
				},
			},
			chgFn:   combine(nonExistentPublicId(), changeName("test-update-name-repo")),
			masks:   []string{nameField},
			wantErr: errors.RecordNotFound,
		},
		{
			name: "empty-field-mask",
			orig: &CredentialLibrary{
				CredentialLibrary: &store.CredentialLibrary{
					HttpMethod: "GET",
					VaultPath:  "/some/path",
					Name:       "test-name-repo",
				},
			},
			chgFn:   changeName("test-update-name-repo"),
			wantErr: errors.EmptyFieldMask,
		},
		{
			name: "read-only-fields-in-field-mask",
			orig: &CredentialLibrary{
				CredentialLibrary: &store.CredentialLibrary{
					HttpMethod: "GET",
					VaultPath:  "/some/path",
					Name:       "test-name-repo",
				},
			},
			chgFn:   changeName("test-update-name-repo"),
			masks:   []string{"PublicId", "CreateTime", "UpdateTime", "StoreId"},
			wantErr: errors.InvalidFieldMask,
		},
		{
			name: "unknown-field-in-field-mask",
			orig: &CredentialLibrary{
				CredentialLibrary: &store.CredentialLibrary{
					HttpMethod: "GET",
					VaultPath:  "/some/path",
					Name:       "test-name-repo",
				},
			},
			chgFn:   changeName("test-update-name-repo"),
			masks:   []string{"Bilbo"},
			wantErr: errors.InvalidFieldMask,
		},
		{
			name: "change-name",
			orig: &CredentialLibrary{
				CredentialLibrary: &store.CredentialLibrary{
					HttpMethod: "GET",
					VaultPath:  "/some/path",
					Name:       "test-name-repo",
				},
			},
			chgFn: changeName("test-update-name-repo"),
			masks: []string{nameField},
			want: &CredentialLibrary{
				CredentialLibrary: &store.CredentialLibrary{
					HttpMethod: "GET",
					VaultPath:  "/some/path",
					Name:       "test-update-name-repo",
				},
			},
			wantCount: 1,
		},
		{
			name: "change-description",
			orig: &CredentialLibrary{
				CredentialLibrary: &store.CredentialLibrary{
					HttpMethod:  "GET",
					VaultPath:   "/some/path",
					Description: "test-description-repo",
				},
			},
			chgFn: changeDescription("test-update-description-repo"),
			masks: []string{descriptionField},
			want: &CredentialLibrary{
				CredentialLibrary: &store.CredentialLibrary{
					HttpMethod:  "GET",
					VaultPath:   "/some/path",
					Description: "test-update-description-repo",
				},
			},
			wantCount: 1,
		},
		{
			name: "change-name-and-description",
			orig: &CredentialLibrary{
				CredentialLibrary: &store.CredentialLibrary{
					HttpMethod:  "GET",
					VaultPath:   "/some/path",
					Name:        "test-name-repo",
					Description: "test-description-repo",
				},
			},
			chgFn: combine(changeDescription("test-update-description-repo"), changeName("test-update-name-repo")),
			masks: []string{nameField, descriptionField},
			want: &CredentialLibrary{
				CredentialLibrary: &store.CredentialLibrary{
					HttpMethod:  "GET",
					VaultPath:   "/some/path",
					Name:        "test-update-name-repo",
					Description: "test-update-description-repo",
				},
			},
			wantCount: 1,
		},
		{
			name: "delete-name",
			orig: &CredentialLibrary{
				CredentialLibrary: &store.CredentialLibrary{
					HttpMethod:  "GET",
					VaultPath:   "/some/path",
					Name:        "test-name-repo",
					Description: "test-description-repo",
				},
			},
			masks: []string{nameField},
			chgFn: combine(changeDescription("test-update-description-repo"), changeName("")),
			want: &CredentialLibrary{
				CredentialLibrary: &store.CredentialLibrary{
					HttpMethod:  "GET",
					VaultPath:   "/some/path",
					Description: "test-description-repo",
				},
			},
			wantCount: 1,
		},
		{
			name: "delete-description",
			orig: &CredentialLibrary{
				CredentialLibrary: &store.CredentialLibrary{
					HttpMethod:  "GET",
					VaultPath:   "/some/path",
					Name:        "test-name-repo",
					Description: "test-description-repo",
				},
			},
			masks: []string{descriptionField},
			chgFn: combine(changeDescription(""), changeName("test-update-name-repo")),
			want: &CredentialLibrary{
				CredentialLibrary: &store.CredentialLibrary{
					HttpMethod: "GET",
					VaultPath:  "/some/path",
					Name:       "test-name-repo",
				},
			},
			wantCount: 1,
		},
		{
			name: "do-not-delete-name",
			orig: &CredentialLibrary{
				CredentialLibrary: &store.CredentialLibrary{
					HttpMethod:  "GET",
					VaultPath:   "/some/path",
					Name:        "test-name-repo",
					Description: "test-description-repo",
				},
			},
			masks: []string{descriptionField},
			chgFn: combine(changeDescription("test-update-description-repo"), changeName("")),
			want: &CredentialLibrary{
				CredentialLibrary: &store.CredentialLibrary{
					HttpMethod:  "GET",
					VaultPath:   "/some/path",
					Name:        "test-name-repo",
					Description: "test-update-description-repo",
				},
			},
			wantCount: 1,
		},
		{
			name: "do-not-delete-description",
			orig: &CredentialLibrary{
				CredentialLibrary: &store.CredentialLibrary{
					HttpMethod:  "GET",
					VaultPath:   "/some/path",
					Name:        "test-name-repo",
					Description: "test-description-repo",
				},
			},
			masks: []string{nameField},
			chgFn: combine(changeDescription(""), changeName("test-update-name-repo")),
			want: &CredentialLibrary{
				CredentialLibrary: &store.CredentialLibrary{
					HttpMethod:  "GET",
					VaultPath:   "/some/path",
					Name:        "test-update-name-repo",
					Description: "test-description-repo",
				},
			},
			wantCount: 1,
		},
		{
			name: "change-vault-path",
			orig: &CredentialLibrary{
				MappingOverride: NewUsernamePasswordOverride(WithOverrideUsernameAttribute("orig-username")),
				CredentialLibrary: &store.CredentialLibrary{
					HttpMethod:     "GET",
					VaultPath:      "/old/path",
					CredentialType: string(globals.UsernamePasswordCredentialType),
				},
			},
			chgFn: changeVaultPath("/new/path"),
			masks: []string{vaultPathField},
			want: &CredentialLibrary{
				MappingOverride: NewUsernamePasswordOverride(WithOverrideUsernameAttribute("orig-username")),
				CredentialLibrary: &store.CredentialLibrary{
					HttpMethod:     "GET",
					VaultPath:      "/new/path",
					CredentialType: string(globals.UsernamePasswordCredentialType),
				},
			},
			wantCount: 1,
		},
		{
			name: "delete-vault-path",
			orig: &CredentialLibrary{
				CredentialLibrary: &store.CredentialLibrary{
					HttpMethod: "GET",
					VaultPath:  "/some/path",
				},
			},
			chgFn:   changeVaultPath(""),
			masks:   []string{vaultPathField},
			wantErr: errors.NotNull,
		},
		{
			name: "change-http-method",
			orig: &CredentialLibrary{
				CredentialLibrary: &store.CredentialLibrary{
					HttpMethod: "GET",
					VaultPath:  "/some/path",
				},
			},
			chgFn: changeHttpMethod(MethodPost),
			masks: []string{httpMethodField},
			want: &CredentialLibrary{
				CredentialLibrary: &store.CredentialLibrary{
					HttpMethod: "POST",
					VaultPath:  "/some/path",
				},
			},
			wantCount: 1,
		},
		{
			name: "delete-http-method",
			orig: &CredentialLibrary{
				CredentialLibrary: &store.CredentialLibrary{
					HttpMethod: "POST",
					VaultPath:  "/some/path",
				},
			},
			chgFn: makeHttpMethodEmptyString(),
			masks: []string{httpMethodField},
			want: &CredentialLibrary{
				CredentialLibrary: &store.CredentialLibrary{
					HttpMethod: "GET",
					VaultPath:  "/some/path",
				},
			},
			wantCount: 1,
		},
		{
			name: "add-http-request-body",
			orig: &CredentialLibrary{
				CredentialLibrary: &store.CredentialLibrary{
					HttpMethod: "POST",
					VaultPath:  "/some/path",
				},
			},
			chgFn: changeHttpRequestBody([]byte("new request body")),
			masks: []string{httpRequestBodyField},
			want: &CredentialLibrary{
				CredentialLibrary: &store.CredentialLibrary{
					HttpMethod:      "POST",
					VaultPath:       "/some/path",
					HttpRequestBody: []byte("new request body"),
				},
			},
			wantCount: 1,
		},
		{
			name: "delete-http-request-body",
			orig: &CredentialLibrary{
				CredentialLibrary: &store.CredentialLibrary{
					HttpMethod:      "POST",
					VaultPath:       "/some/path",
					HttpRequestBody: []byte("request body"),
				},
			},
			chgFn: changeHttpRequestBody(nil),
			masks: []string{httpRequestBodyField},
			want: &CredentialLibrary{
				CredentialLibrary: &store.CredentialLibrary{
					HttpMethod: "POST",
					VaultPath:  "/some/path",
				},
			},
			wantCount: 1,
		},
		{
			name: "change-http-request-body",
			orig: &CredentialLibrary{
				CredentialLibrary: &store.CredentialLibrary{
					HttpMethod:      "POST",
					VaultPath:       "/some/path",
					HttpRequestBody: []byte("old request body"),
				},
			},
			chgFn: changeHttpRequestBody([]byte("new request body")),
			masks: []string{httpRequestBodyField},
			want: &CredentialLibrary{
				CredentialLibrary: &store.CredentialLibrary{
					HttpMethod:      "POST",
					VaultPath:       "/some/path",
					HttpRequestBody: []byte("new request body"),
				},
			},
			wantCount: 1,
		},
		{
			name: "change-method-to-GET-leave-request-body",
			orig: &CredentialLibrary{
				CredentialLibrary: &store.CredentialLibrary{
					HttpMethod:      "POST",
					VaultPath:       "/some/path",
					HttpRequestBody: []byte("old request body"),
				},
			},
			chgFn:   changeHttpMethod(MethodGet),
			masks:   []string{httpMethodField},
			wantErr: errors.CheckConstraint,
		},
		{
			name: "change-method-to-POST-add-request-body",
			orig: &CredentialLibrary{
				CredentialLibrary: &store.CredentialLibrary{
					HttpMethod: "GET",
					VaultPath:  "/some/path",
				},
			},
			chgFn: combine(changeHttpRequestBody([]byte("new request body")), changeHttpMethod(MethodPost)),
			masks: []string{httpRequestBodyField, httpMethodField},
			want: &CredentialLibrary{
				CredentialLibrary: &store.CredentialLibrary{
					HttpMethod:      "POST",
					VaultPath:       "/some/path",
					HttpRequestBody: []byte("new request body"),
				},
			},
			wantCount: 1,
		},
		{
			name: "read-only-credential-type-in-field-mask",
			orig: &CredentialLibrary{
				CredentialLibrary: &store.CredentialLibrary{
					HttpMethod:     "GET",
					VaultPath:      "/some/path",
					Name:           "test-name-repo",
					CredentialType: string(globals.UsernamePasswordCredentialType),
				},
			},
			chgFn:   changeCredentialType(globals.UnspecifiedCredentialType),
			masks:   []string{"PublicId", "CreateTime", "UpdateTime", "StoreId", "CredentialType"},
			wantErr: errors.InvalidFieldMask,
		},
		{
			name: "username-password-attributes-change-username-attribute",
			orig: &CredentialLibrary{
				MappingOverride: NewUsernamePasswordOverride(
					WithOverrideUsernameAttribute("orig-username"),
					WithOverridePasswordAttribute("orig-password"),
				),
				CredentialLibrary: &store.CredentialLibrary{
					HttpMethod:     "GET",
					VaultPath:      "/some/path",
					Name:           "test-name-repo",
					CredentialType: string(globals.UsernamePasswordCredentialType),
				},
			},
			chgFn: changeMappingOverride(
				NewUsernamePasswordOverride(
					WithOverrideUsernameAttribute("changed-username"),
				),
			),
			masks: []string{"MappingOverride"},
			want: &CredentialLibrary{
				MappingOverride: NewUsernamePasswordOverride(
					WithOverrideUsernameAttribute("changed-username"),
				),
				CredentialLibrary: &store.CredentialLibrary{
					HttpMethod:     "GET",
					VaultPath:      "/some/path",
					Name:           "test-name-repo",
					CredentialType: string(globals.UsernamePasswordCredentialType),
				},
			},
			wantCount: 1,
		},
		{
			name: "username-password-attributes-change-password-attribute",
			orig: &CredentialLibrary{
				MappingOverride: NewUsernamePasswordOverride(
					WithOverrideUsernameAttribute("orig-username"),
					WithOverridePasswordAttribute("orig-password"),
				),
				CredentialLibrary: &store.CredentialLibrary{
					HttpMethod:     "GET",
					VaultPath:      "/some/path",
					Name:           "test-name-repo",
					CredentialType: string(globals.UsernamePasswordCredentialType),
				},
			},
			chgFn: changeMappingOverride(
				NewUsernamePasswordOverride(
					WithOverridePasswordAttribute("changed-password"),
				),
			),
			masks: []string{"MappingOverride"},
			want: &CredentialLibrary{
				MappingOverride: NewUsernamePasswordOverride(
					WithOverridePasswordAttribute("changed-password"),
				),
				CredentialLibrary: &store.CredentialLibrary{
					HttpMethod:     "GET",
					VaultPath:      "/some/path",
					Name:           "test-name-repo",
					CredentialType: string(globals.UsernamePasswordCredentialType),
				},
			},
			wantCount: 1,
		},
		{
			name: "username-password-attributes-change-username-and-password-attributes",
			orig: &CredentialLibrary{
				MappingOverride: NewUsernamePasswordOverride(
					WithOverrideUsernameAttribute("orig-username"),
					WithOverridePasswordAttribute("orig-password"),
				),
				CredentialLibrary: &store.CredentialLibrary{
					HttpMethod:     "GET",
					VaultPath:      "/some/path",
					Name:           "test-name-repo",
					CredentialType: string(globals.UsernamePasswordCredentialType),
				},
			},
			chgFn: changeMappingOverride(
				NewUsernamePasswordOverride(
					WithOverrideUsernameAttribute("changed-username"),
					WithOverridePasswordAttribute("changed-password"),
				),
			),
			masks: []string{"MappingOverride"},
			want: &CredentialLibrary{
				MappingOverride: NewUsernamePasswordOverride(
					WithOverrideUsernameAttribute("changed-username"),
					WithOverridePasswordAttribute("changed-password"),
				),
				CredentialLibrary: &store.CredentialLibrary{
					HttpMethod:     "GET",
					VaultPath:      "/some/path",
					Name:           "test-name-repo",
					CredentialType: string(globals.UsernamePasswordCredentialType),
				},
			},
			wantCount: 1,
		},
		{
			name: "no-mapping-override-change-username-and-password-attributes",
			orig: &CredentialLibrary{
				CredentialLibrary: &store.CredentialLibrary{
					HttpMethod:     "GET",
					VaultPath:      "/some/path",
					Name:           "test-name-repo",
					CredentialType: string(globals.UsernamePasswordCredentialType),
				},
			},
			chgFn: changeMappingOverride(
				NewUsernamePasswordOverride(
					WithOverrideUsernameAttribute("changed-username"),
					WithOverridePasswordAttribute("changed-password"),
				),
			),
			masks: []string{"MappingOverride"},
			want: &CredentialLibrary{
				MappingOverride: NewUsernamePasswordOverride(
					WithOverrideUsernameAttribute("changed-username"),
					WithOverridePasswordAttribute("changed-password"),
				),
				CredentialLibrary: &store.CredentialLibrary{
					HttpMethod:     "GET",
					VaultPath:      "/some/path",
					Name:           "test-name-repo",
					CredentialType: string(globals.UsernamePasswordCredentialType),
				},
			},
			wantCount: 1,
		},
		{
			name: "username-password-attributes-delete-mapping-override",
			orig: &CredentialLibrary{
				MappingOverride: NewUsernamePasswordOverride(
					WithOverrideUsernameAttribute("orig-username"),
					WithOverridePasswordAttribute("orig-password"),
				),
				CredentialLibrary: &store.CredentialLibrary{
					HttpMethod:     "GET",
					VaultPath:      "/some/path",
					Name:           "test-name-repo",
					CredentialType: string(globals.UsernamePasswordCredentialType),
				},
			},
			chgFn: changeMappingOverride(nil),
			masks: []string{"MappingOverride"},
			want: &CredentialLibrary{
				CredentialLibrary: &store.CredentialLibrary{
					HttpMethod:     "GET",
					VaultPath:      "/some/path",
					Name:           "test-name-repo",
					CredentialType: string(globals.UsernamePasswordCredentialType),
				},
			},
			wantCount: 1,
		},
		{
			name: "set-mapping-override-on-unspecified-credential-type",
			orig: &CredentialLibrary{
				CredentialLibrary: &store.CredentialLibrary{
					HttpMethod: "GET",
					VaultPath:  "/some/path",
					Name:       "test-name-repo",
				},
			},
			chgFn: changeMappingOverride(
				NewUsernamePasswordOverride(
					WithOverrideUsernameAttribute("changed-username"),
					WithOverridePasswordAttribute("changed-password"),
				),
			),
			masks:   []string{"MappingOverride"},
			wantErr: errors.VaultInvalidMappingOverride,
		},
		{
			name: "password-attribute-change-password-attribute",
			orig: &CredentialLibrary{
				MappingOverride: NewPasswordOverride(
					WithOverridePasswordAttribute("orig-password"),
				),
				CredentialLibrary: &store.CredentialLibrary{
					HttpMethod:     "GET",
					VaultPath:      "/some/path",
					Name:           "test-password-repo",
					CredentialType: string(globals.PasswordCredentialType),
				},
			},
			chgFn: changeMappingOverride(
				NewPasswordOverride(
					WithOverridePasswordAttribute("changed-password"),
				),
			),
			masks: []string{"MappingOverride"},
			want: &CredentialLibrary{
				MappingOverride: NewPasswordOverride(
					WithOverridePasswordAttribute("changed-password"),
				),
				CredentialLibrary: &store.CredentialLibrary{
					HttpMethod:     "GET",
					VaultPath:      "/some/path",
					Name:           "test-password-repo",
					CredentialType: string(globals.PasswordCredentialType),
				},
			},
			wantCount: 1,
		},
		{
			name: "no-mapping-override-change-password-attributes",
			orig: &CredentialLibrary{
				CredentialLibrary: &store.CredentialLibrary{
					HttpMethod:     "GET",
					VaultPath:      "/some/path",
					Name:           "test-password-repo",
					CredentialType: string(globals.PasswordCredentialType),
				},
			},
			chgFn: changeMappingOverride(
				NewPasswordOverride(
					WithOverridePasswordAttribute("changed-password"),
				),
			),
			masks: []string{"MappingOverride"},
			want: &CredentialLibrary{
				MappingOverride: NewPasswordOverride(
					WithOverridePasswordAttribute("changed-password"),
				),
				CredentialLibrary: &store.CredentialLibrary{
					HttpMethod:     "GET",
					VaultPath:      "/some/path",
					Name:           "test-password-repo",
					CredentialType: string(globals.PasswordCredentialType),
				},
			},
			wantCount: 1,
		},
		{
			name: "password-attributes-delete-mapping-override",
			orig: &CredentialLibrary{
				MappingOverride: NewPasswordOverride(
					WithOverridePasswordAttribute("orig-password"),
					WithOverridePrivateKeyAttribute("orig-private-key"),
					WithOverridePrivateKeyPassphraseAttribute("orig-passphrase"),
				),
				CredentialLibrary: &store.CredentialLibrary{
					HttpMethod:     "GET",
					VaultPath:      "/some/path",
					Name:           "test-password-repo",
					CredentialType: string(globals.PasswordCredentialType),
				},
			},
			chgFn: changeMappingOverride(nil),
			masks: []string{"MappingOverride"},
			want: &CredentialLibrary{
				CredentialLibrary: &store.CredentialLibrary{
					HttpMethod:     "GET",
					VaultPath:      "/some/path",
					Name:           "test-password-repo",
					CredentialType: string(globals.PasswordCredentialType),
				},
			},
			wantCount: 1,
		},
		{
			name: "ssh-private-key-attributes-change-username-attribute",
			orig: &CredentialLibrary{
				MappingOverride: NewSshPrivateKeyOverride(
					WithOverrideUsernameAttribute("orig-username"),
				),
				CredentialLibrary: &store.CredentialLibrary{
					HttpMethod:     "GET",
					VaultPath:      "/some/path",
					Name:           "test-ssh-private-key-repo",
					CredentialType: string(globals.SshPrivateKeyCredentialType),
				},
			},
			chgFn: changeMappingOverride(
				NewSshPrivateKeyOverride(
					WithOverrideUsernameAttribute("changed-username"),
				),
			),
			masks: []string{"MappingOverride"},
			want: &CredentialLibrary{
				MappingOverride: NewSshPrivateKeyOverride(
					WithOverrideUsernameAttribute("changed-username"),
				),
				CredentialLibrary: &store.CredentialLibrary{
					HttpMethod:     "GET",
					VaultPath:      "/some/path",
					Name:           "test-ssh-private-key-repo",
					CredentialType: string(globals.SshPrivateKeyCredentialType),
				},
			},
			wantCount: 1,
		},
		{
			name: "ssh-private-key-attributes-change-private-key-attribute",
			orig: &CredentialLibrary{
				MappingOverride: NewSshPrivateKeyOverride(
					WithOverridePrivateKeyAttribute("orig-private-key"),
				),
				CredentialLibrary: &store.CredentialLibrary{
					HttpMethod:     "GET",
					VaultPath:      "/some/path",
					Name:           "test-ssh-private-key-repo",
					CredentialType: string(globals.SshPrivateKeyCredentialType),
				},
			},
			chgFn: changeMappingOverride(
				NewSshPrivateKeyOverride(
					WithOverridePrivateKeyAttribute("changed-private-key"),
				),
			),
			masks: []string{"MappingOverride"},
			want: &CredentialLibrary{
				MappingOverride: NewSshPrivateKeyOverride(
					WithOverridePrivateKeyAttribute("changed-private-key"),
				),
				CredentialLibrary: &store.CredentialLibrary{
					HttpMethod:     "GET",
					VaultPath:      "/some/path",
					Name:           "test-ssh-private-key-repo",
					CredentialType: string(globals.SshPrivateKeyCredentialType),
				},
			},
			wantCount: 1,
		},
		{
			name: "ssh-private-key-attributes-change-passphrase-attribute",
			orig: &CredentialLibrary{
				MappingOverride: NewSshPrivateKeyOverride(
					WithOverridePrivateKeyPassphraseAttribute("orig-passphrase"),
				),
				CredentialLibrary: &store.CredentialLibrary{
					HttpMethod:     "GET",
					VaultPath:      "/some/path",
					Name:           "test-ssh-private-key-repo",
					CredentialType: string(globals.SshPrivateKeyCredentialType),
				},
			},
			chgFn: changeMappingOverride(
				NewSshPrivateKeyOverride(
					WithOverridePrivateKeyPassphraseAttribute("changed-passphrase"),
				),
			),
			masks: []string{"MappingOverride"},
			want: &CredentialLibrary{
				MappingOverride: NewSshPrivateKeyOverride(
					WithOverridePrivateKeyPassphraseAttribute("changed-passphrase"),
				),
				CredentialLibrary: &store.CredentialLibrary{
					HttpMethod:     "GET",
					VaultPath:      "/some/path",
					Name:           "test-ssh-private-key-repo",
					CredentialType: string(globals.SshPrivateKeyCredentialType),
				},
			},
			wantCount: 1,
		},
		{
			name: "ssh-private-key-attributes-change-all-attributes",
			orig: &CredentialLibrary{
				MappingOverride: NewSshPrivateKeyOverride(
					WithOverrideUsernameAttribute("orig-username"),
					WithOverridePrivateKeyAttribute("orig-private-key"),
					WithOverridePrivateKeyPassphraseAttribute("orig-passphrase"),
				),
				CredentialLibrary: &store.CredentialLibrary{
					HttpMethod:     "GET",
					VaultPath:      "/some/path",
					Name:           "test-ssh-private-key-repo",
					CredentialType: string(globals.SshPrivateKeyCredentialType),
				},
			},
			chgFn: changeMappingOverride(
				NewSshPrivateKeyOverride(
					WithOverrideUsernameAttribute("changed-username"),
					WithOverridePrivateKeyAttribute("changed-private-key"),
					WithOverridePrivateKeyPassphraseAttribute("changed-passphrase"),
				),
			),
			masks: []string{"MappingOverride"},
			want: &CredentialLibrary{
				MappingOverride: NewSshPrivateKeyOverride(
					WithOverrideUsernameAttribute("changed-username"),
					WithOverridePrivateKeyAttribute("changed-private-key"),
					WithOverridePrivateKeyPassphraseAttribute("changed-passphrase"),
				),
				CredentialLibrary: &store.CredentialLibrary{
					HttpMethod:     "GET",
					VaultPath:      "/some/path",
					Name:           "test-ssh-private-key-repo",
					CredentialType: string(globals.SshPrivateKeyCredentialType),
				},
			},
			wantCount: 1,
		},
		{
			name: "no-mapping-override-change-all-attributes",
			orig: &CredentialLibrary{
				CredentialLibrary: &store.CredentialLibrary{
					HttpMethod:     "GET",
					VaultPath:      "/some/path",
					Name:           "test-ssh-private-key-repo",
					CredentialType: string(globals.SshPrivateKeyCredentialType),
				},
			},
			chgFn: changeMappingOverride(
				NewSshPrivateKeyOverride(
					WithOverrideUsernameAttribute("changed-username"),
					WithOverridePrivateKeyAttribute("changed-private-key"),
					WithOverridePrivateKeyPassphraseAttribute("changed-passphrase"),
				),
			),
			masks: []string{"MappingOverride"},
			want: &CredentialLibrary{
				MappingOverride: NewSshPrivateKeyOverride(
					WithOverrideUsernameAttribute("changed-username"),
					WithOverridePrivateKeyAttribute("changed-private-key"),
					WithOverridePrivateKeyPassphraseAttribute("changed-passphrase"),
				),
				CredentialLibrary: &store.CredentialLibrary{
					HttpMethod:     "GET",
					VaultPath:      "/some/path",
					Name:           "test-ssh-private-key-repo",
					CredentialType: string(globals.SshPrivateKeyCredentialType),
				},
			},
			wantCount: 1,
		},
		{
			name: "ssh-private-key-attributes-delete-mapping-override",
			orig: &CredentialLibrary{
				MappingOverride: NewSshPrivateKeyOverride(
					WithOverrideUsernameAttribute("orig-username"),
					WithOverridePrivateKeyAttribute("orig-private-key"),
					WithOverridePrivateKeyPassphraseAttribute("orig-passphrase"),
				),
				CredentialLibrary: &store.CredentialLibrary{
					HttpMethod:     "GET",
					VaultPath:      "/some/path",
					Name:           "test-ssh-private-key-repo",
					CredentialType: string(globals.SshPrivateKeyCredentialType),
				},
			},
			chgFn: changeMappingOverride(nil),
			masks: []string{"MappingOverride"},
			want: &CredentialLibrary{
				CredentialLibrary: &store.CredentialLibrary{
					HttpMethod:     "GET",
					VaultPath:      "/some/path",
					Name:           "test-ssh-private-key-repo",
					CredentialType: string(globals.SshPrivateKeyCredentialType),
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
			repo, err := NewRepository(ctx, rw, rw, kms, sche)
			assert.NoError(err)
			require.NotNil(repo)

			_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
			cs := TestCredentialStores(t, conn, wrapper, prj.GetPublicId(), 1)[0]

			tt.orig.StoreId = cs.GetPublicId()
			orig, err := repo.CreateCredentialLibrary(ctx, prj.GetPublicId(), tt.orig)
			assert.NoError(err)
			require.NotNil(orig)

			if tt.chgFn != nil {
				orig = tt.chgFn(orig)
			}
			got, gotCount, err := repo.UpdateCredentialLibrary(ctx, prj.GetPublicId(), orig, 1, tt.masks)
			if tt.wantErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantErr), err), "want err: %q got: %q", tt.wantErr, err)
				assert.Equal(tt.wantCount, gotCount, "row count")
				assert.Nil(got)
				return
			}
			require.NoError(err)
			assert.Empty(tt.orig.PublicId)
			require.NotNil(got)
			assertPublicId(t, globals.VaultCredentialLibraryPrefix, got.GetPublicId())
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

			if tt.wantCount > 0 {
				assert.NoError(db.TestVerifyOplog(t, rw, got.GetPublicId(), db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second)))
			}

			switch w := tt.want.MappingOverride.(type) {
			case nil:
				assert.Nil(got.MappingOverride)
			case *UsernamePasswordOverride:
				g, ok := got.MappingOverride.(*UsernamePasswordOverride)
				require.True(ok)
				assert.Equal(w.UsernameAttribute, g.UsernameAttribute)
				assert.Equal(w.PasswordAttribute, g.PasswordAttribute)
			case *PasswordOverride:
				g, ok := got.MappingOverride.(*PasswordOverride)
				require.True(ok)
				assert.Equal(w.PasswordAttribute, g.PasswordAttribute)
			case *SshPrivateKeyOverride:
				g, ok := got.MappingOverride.(*SshPrivateKeyOverride)
				require.True(ok)
				assert.Equal(w.UsernameAttribute, g.UsernameAttribute)
				assert.Equal(w.PrivateKeyAttribute, g.PrivateKeyAttribute)
				assert.Equal(w.PrivateKeyPassphraseAttribute, g.PrivateKeyPassphraseAttribute)
			default:
				assert.Fail("Unknown mapping override")
			}
		})
	}

	t.Run("invalid-duplicate-names", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		ctx := context.Background()
		kms := kms.TestKms(t, conn, wrapper)
		sche := scheduler.TestScheduler(t, conn, wrapper)
		repo, err := NewRepository(ctx, rw, rw, kms, sche)
		assert.NoError(err)
		require.NotNil(repo)

		name := "test-dup-name"
		_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		cs := TestCredentialStores(t, conn, wrapper, prj.GetPublicId(), 1)[0]
		libs := TestCredentialLibraries(t, conn, wrapper, cs.GetPublicId(), globals.UnspecifiedCredentialType, 2)

		lA, lB := libs[0], libs[1]

		lA.Name = name
		got1, gotCount1, err := repo.UpdateCredentialLibrary(ctx, prj.GetPublicId(), lA, 1, []string{"name"})
		assert.NoError(err)
		require.NotNil(got1)
		assert.Equal(name, got1.Name)
		assert.Equal(1, gotCount1, "row count")
		assert.NoError(db.TestVerifyOplog(t, rw, lA.GetPublicId(), db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second)))

		lB.Name = name
		got2, gotCount2, err := repo.UpdateCredentialLibrary(ctx, prj.GetPublicId(), lB, 1, []string{"name"})
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
		repo, err := NewRepository(ctx, rw, rw, kms, sche)
		assert.NoError(err)
		require.NotNil(repo)

		_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		css := TestCredentialStores(t, conn, wrapper, prj.GetPublicId(), 2)

		csA, csB := css[0], css[1]

		in := &CredentialLibrary{
			CredentialLibrary: &store.CredentialLibrary{
				HttpMethod: "GET",
				VaultPath:  "/some/path",
				Name:       "test-name-repo",
			},
		}
		in2 := in.clone()

		in.StoreId = csA.GetPublicId()
		got, err := repo.CreateCredentialLibrary(ctx, prj.GetPublicId(), in)
		assert.NoError(err)
		require.NotNil(got)
		assertPublicId(t, globals.VaultCredentialLibraryPrefix, got.GetPublicId())
		assert.NotSame(in, got)
		assert.Equal(in.Name, got.Name)
		assert.Equal(in.Description, got.Description)

		in2.StoreId = csB.GetPublicId()
		in2.Name = "first-name"
		got2, err := repo.CreateCredentialLibrary(ctx, prj.GetPublicId(), in2)
		assert.NoError(err)
		require.NotNil(got2)
		got2.Name = got.Name
		got3, gotCount3, err := repo.UpdateCredentialLibrary(ctx, prj.GetPublicId(), got2, 1, []string{"name"})
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
		repo, err := NewRepository(ctx, rw, rw, kms, sche)
		assert.NoError(err)
		require.NotNil(repo)

		_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		css := TestCredentialStores(t, conn, wrapper, prj.GetPublicId(), 1)
		cs := css[0]

		in := &CredentialLibrary{
			CredentialLibrary: &store.CredentialLibrary{
				HttpMethod: "GET",
				VaultPath:  "/some/path",
				Name:       "test-name-repo",
			},
		}

		in.StoreId = cs.GetPublicId()
		got, err := repo.CreateCredentialLibrary(ctx, prj.GetPublicId(), in)
		assert.NoError(err)
		require.NotNil(got)

		// Expire the credential store Vault token
		rows, err := rw.Exec(context.Background(),
			"update credential_vault_token set status = ? where token_hmac = ?",
			[]any{ExpiredToken, cs.Token().TokenHmac})
		require.NoError(err)
		require.Equal(1, rows)

		got.Name = "new-name"
		updated, gotCount, err := repo.UpdateCredentialLibrary(ctx, prj.GetPublicId(), got, 1, []string{"name"})
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
		repo, err := NewRepository(ctx, rw, rw, kms, sche)
		assert.NoError(err)
		require.NotNil(repo)

		_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		css := TestCredentialStores(t, conn, wrapper, prj.GetPublicId(), 2)

		csA, csB := css[0], css[1]

		lA := TestCredentialLibraries(t, conn, wrapper, csA.GetPublicId(), globals.UnspecifiedCredentialType, 1)[0]
		lB := TestCredentialLibraries(t, conn, wrapper, csB.GetPublicId(), globals.UnspecifiedCredentialType, 1)[0]

		assert.NotEqual(lA.StoreId, lB.StoreId)
		orig := lA.clone()

		lA.StoreId = lB.StoreId
		assert.Equal(lA.StoreId, lB.StoreId)

		got1, gotCount1, err := repo.UpdateCredentialLibrary(ctx, prj.GetPublicId(), lA, 1, []string{"name"})

		assert.NoError(err)
		require.NotNil(got1)
		assert.Equal(orig.StoreId, got1.StoreId)
		assert.Equal(1, gotCount1, "row count")
		assert.NoError(db.TestVerifyOplog(t, rw, lA.GetPublicId(), db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second)))
	})
}

func TestRepository_LookupCredentialLibrary(t *testing.T) {
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
			in   *CredentialLibrary
		}{
			{
				name: "valid-no-options",
				in: &CredentialLibrary{
					CredentialLibrary: &store.CredentialLibrary{
						StoreId:    cs.GetPublicId(),
						HttpMethod: "GET",
						VaultPath:  "/some/path",
					},
				},
			},

			{
				name: "valid-with-expired-cred-store-token",
				in: &CredentialLibrary{
					CredentialLibrary: &store.CredentialLibrary{
						StoreId:    csWithExpiredToken.GetPublicId(),
						HttpMethod: "GET",
						VaultPath:  "/some/path",
					},
				},
			},
			{
				name: "valid-username-password-credential-type",
				in: &CredentialLibrary{
					CredentialLibrary: &store.CredentialLibrary{
						StoreId:        cs.GetPublicId(),
						HttpMethod:     "GET",
						VaultPath:      "/some/path",
						CredentialType: string(globals.UsernamePasswordCredentialType),
					},
				},
			},
			{
				name: "valid-username-password-credential-type-with-username-override",
				in: &CredentialLibrary{
					MappingOverride: NewUsernamePasswordOverride(
						WithOverrideUsernameAttribute("utest"),
					),
					CredentialLibrary: &store.CredentialLibrary{
						StoreId:        cs.GetPublicId(),
						HttpMethod:     "GET",
						VaultPath:      "/some/path",
						CredentialType: string(globals.UsernamePasswordCredentialType),
					},
				},
			},
			{
				name: "valid-username-password-credential-type-with-password-override",
				in: &CredentialLibrary{
					MappingOverride: NewUsernamePasswordOverride(
						WithOverridePasswordAttribute("ptest"),
					),
					CredentialLibrary: &store.CredentialLibrary{
						StoreId:        cs.GetPublicId(),
						HttpMethod:     "GET",
						VaultPath:      "/some/path",
						CredentialType: string(globals.UsernamePasswordCredentialType),
					},
				},
			},
			{
				name: "valid-username-password-credential-type-with-username-and-password-override",
				in: &CredentialLibrary{
					MappingOverride: NewUsernamePasswordOverride(
						WithOverrideUsernameAttribute("utest"),
						WithOverridePasswordAttribute("ptest"),
					),
					CredentialLibrary: &store.CredentialLibrary{
						StoreId:        cs.GetPublicId(),
						HttpMethod:     "GET",
						VaultPath:      "/some/path",
						CredentialType: string(globals.UsernamePasswordCredentialType),
					},
				},
			},
			{
				name: "valid-password-credential-type",
				in: &CredentialLibrary{
					CredentialLibrary: &store.CredentialLibrary{
						StoreId:        cs.GetPublicId(),
						HttpMethod:     "GET",
						VaultPath:      "/some/path",
						CredentialType: string(globals.PasswordCredentialType),
					},
				},
			},
			{
				name: "valid-password-credential-type-with-password-override",
				in: &CredentialLibrary{
					MappingOverride: NewPasswordOverride(
						WithOverridePasswordAttribute("ptest"),
					),
					CredentialLibrary: &store.CredentialLibrary{
						StoreId:        cs.GetPublicId(),
						HttpMethod:     "GET",
						VaultPath:      "/some/path",
						CredentialType: string(globals.PasswordCredentialType),
					},
				},
			},
			{
				name: "valid-ssh-private-key-credential-type",
				in: &CredentialLibrary{
					CredentialLibrary: &store.CredentialLibrary{
						StoreId:        cs.GetPublicId(),
						HttpMethod:     "GET",
						VaultPath:      "/some/path",
						CredentialType: string(globals.SshPrivateKeyCredentialType),
					},
				},
			},
			{
				name: "valid-ssh-private-key-credential-type-with-username-override",
				in: &CredentialLibrary{
					MappingOverride: NewSshPrivateKeyOverride(
						WithOverrideUsernameAttribute("utest"),
					),
					CredentialLibrary: &store.CredentialLibrary{
						StoreId:        cs.GetPublicId(),
						HttpMethod:     "GET",
						VaultPath:      "/some/path",
						CredentialType: string(globals.SshPrivateKeyCredentialType),
					},
				},
			},
			{
				name: "valid-ssh-private-key-credential-type-with-private-key-override",
				in: &CredentialLibrary{
					MappingOverride: NewSshPrivateKeyOverride(
						WithOverridePrivateKeyAttribute("ptest"),
					),
					CredentialLibrary: &store.CredentialLibrary{
						StoreId:        cs.GetPublicId(),
						HttpMethod:     "GET",
						VaultPath:      "/some/path",
						CredentialType: string(globals.SshPrivateKeyCredentialType),
					},
				},
			},
			{
				name: "valid-ssh-private-key-credential-type-with-passphrase-override",
				in: &CredentialLibrary{
					MappingOverride: NewSshPrivateKeyOverride(
						WithOverridePrivateKeyPassphraseAttribute("ptest"),
					),
					CredentialLibrary: &store.CredentialLibrary{
						StoreId:        cs.GetPublicId(),
						HttpMethod:     "GET",
						VaultPath:      "/some/path",
						CredentialType: string(globals.SshPrivateKeyCredentialType),
					},
				},
			},
			{
				name: "valid-ssh-private-key-credential-type-with-all-overrides",
				in: &CredentialLibrary{
					MappingOverride: NewSshPrivateKeyOverride(
						WithOverrideUsernameAttribute("utest"),
						WithOverridePrivateKeyAttribute("pktest"),
						WithOverridePrivateKeyPassphraseAttribute("ptest"),
					),
					CredentialLibrary: &store.CredentialLibrary{
						StoreId:        cs.GetPublicId(),
						HttpMethod:     "GET",
						VaultPath:      "/some/path",
						CredentialType: string(globals.SshPrivateKeyCredentialType),
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
				repo, err := NewRepository(ctx, rw, rw, kms, sche)
				assert.NoError(err)
				require.NotNil(repo)
				orig, err := repo.CreateCredentialLibrary(ctx, prj.GetPublicId(), tt.in)
				assert.NoError(err)
				require.NotEmpty(orig)
				// test
				got, err := repo.LookupCredentialLibrary(ctx, orig.GetPublicId())
				assert.NoError(err)
				require.NotEmpty(got)
				assert.Equal(orig.Name, got.Name)
				assert.Equal(orig.Description, got.Description)
				assert.Equal(orig.CredentialType(), got.CredentialType())
				if tt.in.MappingOverride != nil {
					require.NotNil(got.MappingOverride)
					assert.IsType(orig.MappingOverride, got.MappingOverride)
					switch w := orig.MappingOverride.(type) {
					case *UsernamePasswordOverride:
						g, ok := got.MappingOverride.(*UsernamePasswordOverride)
						require.True(ok)
						assert.Equal(w.UsernameAttribute, g.UsernameAttribute)
						assert.Equal(w.PasswordAttribute, g.PasswordAttribute)
					case *PasswordOverride:
						g, ok := got.MappingOverride.(*PasswordOverride)
						require.True(ok)
						assert.Equal(w.PasswordAttribute, g.PasswordAttribute)
					case *SshPrivateKeyOverride:
						g, ok := got.MappingOverride.(*SshPrivateKeyOverride)
						require.True(ok)
						assert.Equal(w.UsernameAttribute, g.UsernameAttribute)
						assert.Equal(w.PrivateKeyAttribute, g.PrivateKeyAttribute)
						assert.Equal(w.PrivateKeyPassphraseAttribute, g.PrivateKeyPassphraseAttribute)
					default:
						assert.Fail("Unknown mapping override")
					}
				}
			})
		}
	}

	t.Run("empty-public-id", func(t *testing.T) {
		// setup
		assert, require := assert.New(t), require.New(t)
		ctx := context.Background()
		kms := kms.TestKms(t, conn, wrapper)
		sche := scheduler.TestScheduler(t, conn, wrapper)
		repo, err := NewRepository(ctx, rw, rw, kms, sche)
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
		repo, err := NewRepository(ctx, rw, rw, kms, sche)
		assert.NoError(err)
		require.NotNil(repo)
		badId, err := newCredentialLibraryId(ctx)
		assert.NoError(err)
		require.NotNil(badId)
		// test
		got, err := repo.LookupCredentialLibrary(ctx, badId)
		assert.NoError(err)
		assert.Empty(got)
	})
}

func TestRepository_DeleteCredentialLibrary(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)

	{
		_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		cs := TestCredentialStores(t, conn, wrapper, prj.GetPublicId(), 1)[0]
		l := TestCredentialLibraries(t, conn, wrapper, cs.GetPublicId(), globals.UnspecifiedCredentialType, 1)[0]

		badId, err := newCredentialLibraryId(ctx)
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
				kms := kms.TestKms(t, conn, wrapper)
				sche := scheduler.TestScheduler(t, conn, wrapper)
				repo, err := NewRepository(ctx, rw, rw, kms, sche)
				assert.NoError(err)
				require.NotNil(repo)

				got, err := repo.DeleteCredentialLibrary(ctx, prj.GetPublicId(), tt.in)
				if tt.wantErr != 0 {
					assert.Truef(errors.Match(errors.T(tt.wantErr), err), "want err: %q got: %q", tt.wantErr, err)
					return
				}
				assert.NoError(err)
				assert.Equal(tt.want, got, "row count")
			})
		}
	}

	t.Run("library-with-mapping-overrides", func(t *testing.T) {
		// setup
		assert, require := assert.New(t), require.New(t)

		kms := kms.TestKms(t, conn, wrapper)
		sche := scheduler.TestScheduler(t, conn, wrapper)
		repo, err := NewRepository(ctx, rw, rw, kms, sche)
		assert.NoError(err)
		require.NotNil(repo)

		_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		cs := TestCredentialStores(t, conn, wrapper, prj.GetPublicId(), 1)[0]
		lib := &CredentialLibrary{
			MappingOverride: NewUsernamePasswordOverride(
				WithOverrideUsernameAttribute("orig-username"),
				WithOverridePasswordAttribute("orig-password"),
			),
			CredentialLibrary: &store.CredentialLibrary{
				StoreId:        cs.GetPublicId(),
				HttpMethod:     "GET",
				VaultPath:      "/some/path",
				Name:           "test-name-repo",
				CredentialType: string(globals.UsernamePasswordCredentialType),
			},
		}

		orig, err := repo.CreateCredentialLibrary(ctx, prj.GetPublicId(), lib)
		assert.NoError(err)
		require.NotNil(orig)

		// test
		got, err := repo.DeleteCredentialLibrary(ctx, prj.GetPublicId(), orig.GetPublicId())
		assert.NoError(err)
		assert.Equal(1, got)
	})
}

func TestRepository_ListCredentialLibraries(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)

	t.Run("CredentialStore-with-a-library", func(t *testing.T) {
		// setup
		assert, require := assert.New(t), require.New(t)

		ctx := context.Background()
		kms := kms.TestKms(t, conn, wrapper)
		sche := scheduler.TestScheduler(t, conn, wrapper)
		repo, err := NewRepository(ctx, rw, rw, kms, sche)
		assert.NoError(err)
		require.NotNil(repo)

		_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		cs := TestCredentialStores(t, conn, wrapper, prj.GetPublicId(), 2)[0]
		lib := &CredentialLibrary{
			MappingOverride: NewUsernamePasswordOverride(
				WithOverrideUsernameAttribute("orig-username"),
				WithOverridePasswordAttribute("orig-password"),
			),
			CredentialLibrary: &store.CredentialLibrary{
				StoreId:        cs.GetPublicId(),
				HttpMethod:     "GET",
				VaultPath:      "/some/path",
				Name:           "test-name-repo",
				CredentialType: string(globals.UsernamePasswordCredentialType),
			},
		}

		orig, err := repo.CreateCredentialLibrary(ctx, prj.GetPublicId(), lib)
		assert.NoError(err)
		require.NotNil(orig)

		// test
		got, ttime, err := repo.ListLibraries(ctx, cs.GetPublicId())
		assert.NoError(err)
		require.Len(got, 1)
		// Transaction timestamp should be within ~10 seconds of now
		assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
		assert.True(time.Now().After(ttime.Add(-10 * time.Second)))
		require.Empty(cmp.Diff(
			orig,
			got[0],
			cmpopts.IgnoreUnexported(
				CredentialLibrary{},
				store.CredentialLibrary{},
				timestamp.Timestamp{},
				timestamppb.Timestamp{},
			),
			cmpopts.IgnoreFields(
				CredentialLibrary{},
				"MappingOverride",
			),
		))
	})

	t.Run("with-no-credential-store-id", func(t *testing.T) {
		// setup
		assert, require := assert.New(t), require.New(t)
		ctx := context.Background()
		kms := kms.TestKms(t, conn, wrapper)
		sche := scheduler.TestScheduler(t, conn, wrapper)
		repo, err := NewRepository(ctx, rw, rw, kms, sche)
		assert.NoError(err)
		require.NotNil(repo)
		// test
		_, _, err = repo.ListLibraries(ctx, "")
		wantErr := errors.InvalidParameter
		assert.Truef(errors.Match(errors.T(wantErr), err), "want err: %q got: %q", wantErr, err)
	})

	t.Run("CredentialStore-with-no-libraries", func(t *testing.T) {
		// setup
		assert, require := assert.New(t), require.New(t)
		ctx := context.Background()
		kms := kms.TestKms(t, conn, wrapper)
		sche := scheduler.TestScheduler(t, conn, wrapper)
		repo, err := NewRepository(ctx, rw, rw, kms, sche)
		assert.NoError(err)
		require.NotNil(repo)
		_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		cs := TestCredentialStores(t, conn, wrapper, prj.GetPublicId(), 1)[0]
		// test
		got, ttime, err := repo.ListLibraries(ctx, cs.GetPublicId())
		assert.NoError(err)
		assert.Empty(got)
		// Transaction timestamp should be within ~10 seconds of now
		assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
		assert.True(time.Now().After(ttime.Add(-10 * time.Second)))
	})
}

func TestRepository_ListCredentialLibraries_Limits(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	sche := scheduler.TestScheduler(t, conn, wrapper)

	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	cs := TestCredentialStores(t, conn, wrapper, prj.GetPublicId(), 1)[0]
	const count = 10
	libs := TestCredentialLibraries(t, conn, wrapper, cs.GetPublicId(), globals.UnspecifiedCredentialType, count)

	tests := []struct {
		name     string
		repoOpts []Option
		listOpts []credential.Option
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
			name:     "with-list-limit",
			listOpts: []credential.Option{credential.WithLimit(3)},
			wantLen:  3,
		},
		{
			name:     "with-repo-smaller-than-list-limit",
			repoOpts: []Option{WithLimit(2)},
			listOpts: []credential.Option{credential.WithLimit(6)},
			wantLen:  6,
		},
		{
			name:     "with-repo-larger-than-list-limit",
			repoOpts: []Option{WithLimit(6)},
			listOpts: []credential.Option{credential.WithLimit(2)},
			wantLen:  2,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			ctx := context.Background()
			kms := kms.TestKms(t, conn, wrapper)
			repo, err := NewRepository(ctx, rw, rw, kms, sche, tt.repoOpts...)
			assert.NoError(err)
			require.NotNil(repo)
			got, ttime, err := repo.ListLibraries(ctx, libs[0].StoreId, tt.listOpts...)
			require.NoError(err)
			assert.Len(got, tt.wantLen)
			// Transaction timestamp should be within ~10 seconds of now
			assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
			assert.True(time.Now().After(ttime.Add(-10 * time.Second)))
		})
	}
}

func TestRepository_ListCredentialLibraries_Pagination(t *testing.T) {
	t.Parallel()
	assert, require := assert.New(t), require.New(t)
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	sche := scheduler.TestScheduler(t, conn, wrapper)
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	css := TestCredentialStores(t, conn, wrapper, prj.GetPublicId(), 3)

	for _, cs := range css[:2] { // Leave the third store empty
		TestCredentialLibraries(t, conn, wrapper, cs.GetPublicId(), globals.UnspecifiedCredentialType, 5)
	}
	repo, err := NewRepository(ctx, rw, rw, kms, sche)
	require.NoError(err)
	require.NotNil(repo)

	for _, cs := range css[:2] {
		page1, ttime, err := repo.ListLibraries(ctx, cs.GetPublicId(), credential.WithLimit(2))
		require.NoError(err)
		require.Len(page1, 2)
		// Transaction timestamp should be within ~10 seconds of now
		assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
		assert.True(time.Now().After(ttime.Add(-10 * time.Second)))
		page2, ttime, err := repo.ListLibraries(ctx, cs.GetPublicId(), credential.WithLimit(2), credential.WithStartPageAfterItem(page1[1]))
		require.NoError(err)
		require.Len(page2, 2)
		assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
		assert.True(time.Now().After(ttime.Add(-10 * time.Second)))
		for _, item := range page1 {
			assert.NotEqual(item.GetPublicId(), page2[0].GetPublicId())
			assert.NotEqual(item.GetPublicId(), page2[1].GetPublicId())
		}
		page3, ttime, err := repo.ListLibraries(ctx, cs.GetPublicId(), credential.WithLimit(2), credential.WithStartPageAfterItem(page2[1]))
		require.NoError(err)
		require.Len(page3, 1)
		assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
		assert.True(time.Now().After(ttime.Add(-10 * time.Second)))
		for _, item := range append(page1, page2...) {
			assert.NotEqual(item.GetPublicId(), page3[0].GetPublicId())
		}
		page4, ttime, err := repo.ListLibraries(ctx, cs.GetPublicId(), credential.WithLimit(2), credential.WithStartPageAfterItem(page3[0]))
		require.NoError(err)
		require.Empty(page4)
		assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
		assert.True(time.Now().After(ttime.Add(-10 * time.Second)))
	}

	emptyPage, ttime, err := repo.ListLibraries(ctx, css[2].GetPublicId(), credential.WithLimit(2))
	require.NoError(err)
	assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
	assert.True(time.Now().After(ttime.Add(-10 * time.Second)))
	require.Empty(emptyPage)
}

func TestRepository_ListDeletedLibraryIds(t *testing.T) {
	t.Parallel()
	require := require.New(t)
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	sche := scheduler.TestScheduler(t, conn, wrapper)
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	store := TestCredentialStores(t, conn, wrapper, prj.GetPublicId(), 1)[0]
	libs := TestCredentialLibraries(t, conn, wrapper, store.GetPublicId(), globals.UnspecifiedCredentialType, 2)

	repo, err := NewRepository(ctx, rw, rw, kms, sche)
	require.NoError(err)
	require.NotNil(repo)

	// Expect no entries at the start
	deletedIds, ttime, err := repo.ListDeletedLibraryIds(ctx, time.Now().AddDate(-1, 0, 0))
	require.NoError(err)
	require.Empty(deletedIds)
	// Transaction timestamp should be within ~10 seconds of now
	assert.True(t, time.Now().Before(ttime.Add(10*time.Second)))
	assert.True(t, time.Now().After(ttime.Add(-10*time.Second)))

	// Delete a vault library
	_, err = repo.DeleteCredentialLibrary(ctx, prj.GetPublicId(), libs[0].GetPublicId())
	require.NoError(err)

	// Expect a single entry
	deletedIds, ttime, err = repo.ListDeletedLibraryIds(ctx, time.Now().AddDate(-1, 0, 0))
	require.NoError(err)
	require.Equal([]string{libs[0].GetPublicId()}, deletedIds)
	assert.True(t, time.Now().Before(ttime.Add(10*time.Second)))
	assert.True(t, time.Now().After(ttime.Add(-10*time.Second)))

	// Try again with the time set to now, expect no entries
	deletedIds, ttime, err = repo.ListDeletedLibraryIds(ctx, time.Now())
	require.NoError(err)
	require.Empty(deletedIds)
	assert.True(t, time.Now().Before(ttime.Add(10*time.Second)))
	assert.True(t, time.Now().After(ttime.Add(-10*time.Second)))
}

func TestRepository_EstimatedLibraryCount(t *testing.T) {
	t.Parallel()
	assert, require := assert.New(t), require.New(t)
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	sqlDb, err := conn.SqlDB(ctx)
	require.NoError(err)
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	sche := scheduler.TestScheduler(t, conn, wrapper)
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	store := TestCredentialStores(t, conn, wrapper, prj.GetPublicId(), 1)[0]

	repo, err := NewRepository(ctx, rw, rw, kms, sche)
	require.NoError(err)
	require.NotNil(repo)

	// Check total entries at start, expect 0
	numItems, err := repo.EstimatedLibraryCount(ctx)
	require.NoError(err)
	assert.Equal(0, numItems)

	// Create some libraries
	libs := TestCredentialLibraries(t, conn, wrapper, store.GetPublicId(), globals.UnspecifiedCredentialType, 2)
	// Run analyze to update postgres meta tables
	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(err)

	numItems, err = repo.EstimatedLibraryCount(ctx)
	require.NoError(err)
	assert.Equal(2, numItems)

	// Delete a library
	_, err = repo.DeleteCredentialLibrary(ctx, prj.GetPublicId(), libs[0].GetPublicId())
	require.NoError(err)
	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(err)

	numItems, err = repo.EstimatedLibraryCount(ctx)
	require.NoError(err)
	assert.Equal(1, numItems)
}
