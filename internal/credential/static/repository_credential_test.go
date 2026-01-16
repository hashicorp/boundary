// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package static

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/credential/static/store"
	"github.com/hashicorp/boundary/internal/db"
	dbassert "github.com/hashicorp/boundary/internal/db/assert"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/libs/crypto"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh/testdata"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestRepository_CreateUsernamePasswordCredential(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))

	cs := TestCredentialStore(t, conn, wrapper, prj.PublicId)

	tests := []struct {
		name        string
		projectId   string
		cred        *UsernamePasswordCredential
		wantErr     bool
		wantErrCode errors.Code
	}{
		{
			name:        "missing-store",
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
		},
		{
			name:        "missing-embedded-cred",
			cred:        &UsernamePasswordCredential{},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
		},
		{
			name: "missing-project-id",
			cred: &UsernamePasswordCredential{
				UsernamePasswordCredential: &store.UsernamePasswordCredential{
					Username: "my-user",
					Password: []byte("secret"),
					StoreId:  cs.PublicId,
				},
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
		},
		{
			name:      "missing-username",
			projectId: prj.PublicId,
			cred: &UsernamePasswordCredential{
				UsernamePasswordCredential: &store.UsernamePasswordCredential{
					Password: []byte("secret"),
					StoreId:  cs.PublicId,
				},
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
		},
		{
			name:      "missing-password",
			projectId: prj.PublicId,
			cred: &UsernamePasswordCredential{
				UsernamePasswordCredential: &store.UsernamePasswordCredential{
					Username: "my-user",
					StoreId:  cs.PublicId,
				},
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
		},
		{
			name:      "missing-store-id",
			projectId: prj.PublicId,
			cred: &UsernamePasswordCredential{
				UsernamePasswordCredential: &store.UsernamePasswordCredential{
					Username: "my-user",
					Password: []byte("secret"),
				},
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
		},
		{
			name:      "valid",
			projectId: prj.PublicId,
			cred: &UsernamePasswordCredential{
				UsernamePasswordCredential: &store.UsernamePasswordCredential{
					Username: "my-user",
					Password: []byte("secret"),
					StoreId:  cs.PublicId,
				},
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			ctx := context.Background()
			kkms := kms.TestKms(t, conn, wrapper)
			repo, err := NewRepository(ctx, rw, rw, kkms)
			require.NoError(err)
			require.NotNil(repo)

			got, err := repo.CreateUsernamePasswordCredential(ctx, tt.projectId, tt.cred)
			if tt.wantErr {
				assert.Truef(errors.Match(errors.T(tt.wantErr), err), "want err: %q got: %q", tt.wantErr, err)
				assert.Nil(got)
				return
			}
			require.NoError(err)
			assertPublicId(t, globals.UsernamePasswordCredentialPrefix, got.PublicId)
			assert.Equal(tt.cred.Username, got.Username)
			assert.Nil(got.Password)
			assert.Nil(got.CtPassword)

			// Validate password
			lookupCred := allocUsernamePasswordCredential()
			lookupCred.PublicId = got.PublicId
			require.NoError(rw.LookupById(ctx, lookupCred))

			databaseWrapper, err := kkms.GetWrapper(context.Background(), tt.projectId, kms.KeyPurposeDatabase)
			require.NoError(err)
			require.NoError(lookupCred.decrypt(ctx, databaseWrapper))
			assert.Equal(tt.cred.Password, lookupCred.Password)

			assert.Empty(got.Password)
			assert.Empty(got.CtPassword)
			assert.NotEmpty(got.PasswordHmac)

			// Validate hmac
			hm, err := crypto.HmacSha256(ctx, tt.cred.Password, databaseWrapper, []byte(tt.cred.StoreId), nil, crypto.WithEd25519())
			require.NoError(err)
			assert.Equal([]byte(hm), got.PasswordHmac)

			// Validate oplog
			assert.NoError(db.TestVerifyOplog(t, rw, got.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second)))
		})
	}

	t.Run("duplicate-names", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		ctx := context.Background()
		kms := kms.TestKms(t, conn, wrapper)
		repo, err := NewRepository(ctx, rw, rw, kms)
		require.NoError(err)
		require.NotNil(repo)
		org, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		prj2 := iam.TestProject(t, iam.TestRepo(t, conn, wrapper), org.GetPublicId())
		require.NoError(err)

		prjCs := TestCredentialStore(t, conn, wrapper, prj.GetPublicId())
		prj2Cs := TestCredentialStore(t, conn, wrapper, prj2.GetPublicId())

		in, err := NewUsernamePasswordCredential(prjCs.GetPublicId(), "user", "pass", WithName("my-name"), WithDescription("original"))
		assert.NoError(err)

		got, err := repo.CreateUsernamePasswordCredential(ctx, prj.PublicId, in)
		require.NoError(err)
		assert.Equal(in.Name, got.Name)
		assert.Equal(in.Description, got.Description)

		in2, err := NewUsernamePasswordCredential(prjCs.GetPublicId(), "user", "pass", WithName("my-name"), WithDescription("different"))
		require.NoError(err)
		got2, err := repo.CreateUsernamePasswordCredential(ctx, prj.GetPublicId(), in2)
		assert.Truef(errors.Match(errors.T(errors.NotUnique), err), "want err code: %v got err: %v", errors.NotUnique, err)
		assert.Nil(got2)

		// Creating credential in different project should not conflict
		in3, err := NewUsernamePasswordCredential(prj2Cs.GetPublicId(), "user", "pass", WithName("my-name"), WithDescription("different"))
		require.NoError(err)
		got3, err := repo.CreateUsernamePasswordCredential(ctx, prj2.GetPublicId(), in3)
		require.NoError(err)
		assert.Equal(in3.Name, got3.Name)
		assert.Equal(in3.Description, got3.Description)

		assert.NotEqual(got.PublicId, got3.PublicId)
	})
}

func TestRepository_CreateUsernamePasswordDomainCredential(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))

	cs := TestCredentialStore(t, conn, wrapper, prj.PublicId)

	tests := []struct {
		name        string
		projectId   string
		cred        *UsernamePasswordDomainCredential
		wantErr     bool
		wantErrCode errors.Code
	}{
		{
			name:        "missing-store",
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
		},
		{
			name:        "missing-embedded-cred",
			cred:        &UsernamePasswordDomainCredential{},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
		},
		{
			name: "missing-project-id",
			cred: &UsernamePasswordDomainCredential{
				UsernamePasswordDomainCredential: &store.UsernamePasswordDomainCredential{
					Username: "my-user",
					Password: []byte("secret"),
					Domain:   "domain.com",
					StoreId:  cs.PublicId,
				},
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
		},
		{
			name:      "missing-username",
			projectId: prj.PublicId,
			cred: &UsernamePasswordDomainCredential{
				UsernamePasswordDomainCredential: &store.UsernamePasswordDomainCredential{
					Password: []byte("secret"),
					Domain:   "domain.com",
					StoreId:  cs.PublicId,
				},
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
		},
		{
			name:      "missing-domain",
			projectId: prj.PublicId,
			cred: &UsernamePasswordDomainCredential{
				UsernamePasswordDomainCredential: &store.UsernamePasswordDomainCredential{
					Username: "my-user",
					Password: []byte("secret"),
					StoreId:  cs.PublicId,
				},
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
		},
		{
			name:      "missing-password",
			projectId: prj.PublicId,
			cred: &UsernamePasswordDomainCredential{
				UsernamePasswordDomainCredential: &store.UsernamePasswordDomainCredential{
					Username: "my-user",
					Domain:   "domain.com",
					StoreId:  cs.PublicId,
				},
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
		},
		{
			name:      "missing-store-id",
			projectId: prj.PublicId,
			cred: &UsernamePasswordDomainCredential{
				UsernamePasswordDomainCredential: &store.UsernamePasswordDomainCredential{
					Username: "my-user",
					Password: []byte("secret"),
					Domain:   "domain.com",
				},
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
		},
		{
			name:      "valid",
			projectId: prj.PublicId,
			cred: &UsernamePasswordDomainCredential{
				UsernamePasswordDomainCredential: &store.UsernamePasswordDomainCredential{
					Username: "my-user",
					Password: []byte("secret"),
					Domain:   "domain.com",
					StoreId:  cs.PublicId,
				},
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			ctx := context.Background()
			kkms := kms.TestKms(t, conn, wrapper)
			repo, err := NewRepository(ctx, rw, rw, kkms)
			require.NoError(err)
			require.NotNil(repo)

			got, err := repo.CreateUsernamePasswordDomainCredential(ctx, tt.projectId, tt.cred)
			if tt.wantErr {
				assert.Truef(errors.Match(errors.T(tt.wantErr), err), "want err: %q got: %q", tt.wantErr, err)
				assert.Nil(got)
				return
			}
			require.NoError(err)
			assertPublicId(t, globals.UsernamePasswordDomainCredentialPrefix, got.PublicId)
			assert.Equal(tt.cred.Username, got.Username)
			assert.Nil(got.Password)
			assert.Nil(got.CtPassword)

			// Validate password
			lookupCred := allocUsernamePasswordDomainCredential()
			lookupCred.PublicId = got.PublicId
			require.NoError(rw.LookupById(ctx, lookupCred))

			databaseWrapper, err := kkms.GetWrapper(context.Background(), tt.projectId, kms.KeyPurposeDatabase)
			require.NoError(err)
			require.NoError(lookupCred.decrypt(ctx, databaseWrapper))
			assert.Equal(tt.cred.Password, lookupCred.Password)

			assert.Empty(got.Password)
			assert.Empty(got.CtPassword)
			assert.NotEmpty(got.PasswordHmac)

			// Validate hmac
			hm, err := crypto.HmacSha256(ctx, tt.cred.Password, databaseWrapper, []byte(tt.cred.StoreId), nil, crypto.WithEd25519())
			require.NoError(err)
			assert.Equal([]byte(hm), got.PasswordHmac)

			// Validate oplog
			assert.NoError(db.TestVerifyOplog(t, rw, got.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second)))
		})
	}

	t.Run("duplicate-names", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		ctx := context.Background()
		kms := kms.TestKms(t, conn, wrapper)
		repo, err := NewRepository(ctx, rw, rw, kms)
		require.NoError(err)
		require.NotNil(repo)
		org, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		prj2 := iam.TestProject(t, iam.TestRepo(t, conn, wrapper), org.GetPublicId())
		require.NoError(err)

		prjCs := TestCredentialStore(t, conn, wrapper, prj.GetPublicId())
		prj2Cs := TestCredentialStore(t, conn, wrapper, prj2.GetPublicId())

		in, err := NewUsernamePasswordDomainCredential(prjCs.GetPublicId(), "user", "pass", "domain.com", WithName("my-name"), WithDescription("original"))
		assert.NoError(err)

		got, err := repo.CreateUsernamePasswordDomainCredential(ctx, prj.PublicId, in)
		require.NoError(err)
		assert.Equal(in.Name, got.Name)
		assert.Equal(in.Description, got.Description)

		in2, err := NewUsernamePasswordDomainCredential(prjCs.GetPublicId(), "user", "pass", "domain.com", WithName("my-name"), WithDescription("different"))
		require.NoError(err)
		got2, err := repo.CreateUsernamePasswordDomainCredential(ctx, prj.GetPublicId(), in2)
		assert.Truef(errors.Match(errors.T(errors.NotUnique), err), "want err code: %v got err: %v", errors.NotUnique, err)
		assert.Nil(got2)

		// Creating credential in different project should not conflict
		in3, err := NewUsernamePasswordDomainCredential(prj2Cs.GetPublicId(), "user", "pass", "domain.com", WithName("my-name"), WithDescription("different"))
		require.NoError(err)
		got3, err := repo.CreateUsernamePasswordDomainCredential(ctx, prj2.GetPublicId(), in3)
		require.NoError(err)
		assert.Equal(in3.Name, got3.Name)
		assert.Equal(in3.Description, got3.Description)

		assert.NotEqual(got.PublicId, got3.PublicId)
	})
}

func TestRepository_CreatePasswordCredential(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))

	cs := TestCredentialStore(t, conn, wrapper, prj.PublicId)

	tests := []struct {
		name        string
		projectId   string
		cred        *PasswordCredential
		wantErr     bool
		wantErrCode errors.Code
	}{
		{
			name:        "missing-store",
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
		},
		{
			name:        "missing-embedded-cred",
			cred:        &PasswordCredential{},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
		},
		{
			name: "missing-project-id",
			cred: &PasswordCredential{
				PasswordCredential: &store.PasswordCredential{
					Password: []byte("secret"),
					StoreId:  cs.PublicId,
				},
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
		},
		{
			name:      "missing-password",
			projectId: prj.PublicId,
			cred: &PasswordCredential{
				PasswordCredential: &store.PasswordCredential{
					StoreId: cs.PublicId,
				},
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
		},
		{
			name:      "missing-store-id",
			projectId: prj.PublicId,
			cred: &PasswordCredential{
				PasswordCredential: &store.PasswordCredential{
					Password: []byte("secret"),
				},
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
		},
		{
			name:      "valid",
			projectId: prj.PublicId,
			cred: &PasswordCredential{
				PasswordCredential: &store.PasswordCredential{
					Password: []byte("secret"),
					StoreId:  cs.PublicId,
				},
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			ctx := context.Background()
			kkms := kms.TestKms(t, conn, wrapper)
			repo, err := NewRepository(ctx, rw, rw, kkms)
			require.NoError(err)
			require.NotNil(repo)

			got, err := repo.CreatePasswordCredential(ctx, tt.projectId, tt.cred)
			if tt.wantErr {
				assert.Truef(errors.Match(errors.T(tt.wantErr), err), "want err: %q got: %q", tt.wantErr, err)
				assert.Nil(got)
				return
			}
			require.NoError(err)
			assertPublicId(t, globals.PasswordCredentialPrefix, got.PublicId)
			assert.Nil(got.Password)
			assert.Nil(got.CtPassword)

			// Validate password
			lookupCred := allocPasswordCredential()
			lookupCred.PublicId = got.PublicId
			require.NoError(rw.LookupById(ctx, lookupCred))

			databaseWrapper, err := kkms.GetWrapper(context.Background(), tt.projectId, kms.KeyPurposeDatabase)
			require.NoError(err)
			require.NoError(lookupCred.decrypt(ctx, databaseWrapper))
			assert.Equal(tt.cred.Password, lookupCred.Password)

			assert.Empty(got.Password)
			assert.Empty(got.CtPassword)
			assert.NotEmpty(got.PasswordHmac)

			// Validate hmac
			hm, err := crypto.HmacSha256(ctx, tt.cred.Password, databaseWrapper, []byte(tt.cred.StoreId), nil, crypto.WithEd25519())
			require.NoError(err)
			assert.Equal([]byte(hm), got.PasswordHmac)

			// Validate oplog
			assert.NoError(db.TestVerifyOplog(t, rw, got.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second)))
		})
	}

	t.Run("duplicate-names", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		ctx := context.Background()
		kms := kms.TestKms(t, conn, wrapper)
		repo, err := NewRepository(ctx, rw, rw, kms)
		require.NoError(err)
		require.NotNil(repo)
		org, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		prj2 := iam.TestProject(t, iam.TestRepo(t, conn, wrapper), org.GetPublicId())
		require.NoError(err)

		prjCs := TestCredentialStore(t, conn, wrapper, prj.GetPublicId())
		prj2Cs := TestCredentialStore(t, conn, wrapper, prj2.GetPublicId())

		in, err := NewPasswordCredential(prjCs.GetPublicId(), "pass", WithName("my-name"), WithDescription("original"))
		assert.NoError(err)

		got, err := repo.CreatePasswordCredential(ctx, prj.PublicId, in)
		require.NoError(err)
		assert.Equal(in.Name, got.Name)
		assert.Equal(in.Description, got.Description)

		in2, err := NewPasswordCredential(prjCs.GetPublicId(), "pass", WithName("my-name"), WithDescription("different"))
		require.NoError(err)
		got2, err := repo.CreatePasswordCredential(ctx, prj.GetPublicId(), in2)
		assert.Truef(errors.Match(errors.T(errors.NotUnique), err), "want err code: %v got err: %v", errors.NotUnique, err)
		assert.Nil(got2)

		// Creating credential in different project should not conflict
		in3, err := NewPasswordCredential(prj2Cs.GetPublicId(), "pass", WithName("my-name"), WithDescription("different"))
		require.NoError(err)
		got3, err := repo.CreatePasswordCredential(ctx, prj2.GetPublicId(), in3)
		require.NoError(err)
		assert.Equal(in3.Name, got3.Name)
		assert.Equal(in3.Description, got3.Description)

		assert.NotEqual(got.PublicId, got3.PublicId)
	})
}

func TestRepository_CreateSshPrivateKeyCredential(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))

	cs := TestCredentialStore(t, conn, wrapper, prj.PublicId)

	tests := []struct {
		name        string
		projectId   string
		cred        *SshPrivateKeyCredential
		wantErr     bool
		wantErrCode errors.Code
	}{
		{
			name:        "missing-store",
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
		},
		{
			name:        "missing-embedded-cred",
			cred:        &SshPrivateKeyCredential{},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
		},
		{
			name: "missing-project-id",
			cred: &SshPrivateKeyCredential{
				SshPrivateKeyCredential: &store.SshPrivateKeyCredential{
					Username:   "my-user",
					PrivateKey: []byte(TestSshPrivateKeyPem),
					StoreId:    cs.PublicId,
				},
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
		},
		{
			name:      "missing-username",
			projectId: prj.PublicId,
			cred: &SshPrivateKeyCredential{
				SshPrivateKeyCredential: &store.SshPrivateKeyCredential{
					PrivateKey: []byte(TestSshPrivateKeyPem),
					StoreId:    cs.PublicId,
				},
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
		},
		{
			name:      "missing-private-key",
			projectId: prj.PublicId,
			cred: &SshPrivateKeyCredential{
				SshPrivateKeyCredential: &store.SshPrivateKeyCredential{
					Username: "my-user",
					StoreId:  cs.PublicId,
				},
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
		},
		{
			name:      "missing-store-id",
			projectId: prj.PublicId,
			cred: &SshPrivateKeyCredential{
				SshPrivateKeyCredential: &store.SshPrivateKeyCredential{
					Username:   "my-user",
					PrivateKey: []byte(TestSshPrivateKeyPem),
				},
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
		},
		{
			name:      "valid",
			projectId: prj.PublicId,
			cred: &SshPrivateKeyCredential{
				SshPrivateKeyCredential: &store.SshPrivateKeyCredential{
					Username:   "my-user",
					PrivateKey: []byte(TestSshPrivateKeyPem),
					StoreId:    cs.PublicId,
				},
			},
		},
		{
			name:      "valid-large-pk",
			projectId: prj.PublicId,
			cred: &SshPrivateKeyCredential{
				SshPrivateKeyCredential: &store.SshPrivateKeyCredential{
					Username:   "my-user",
					PrivateKey: []byte(TestLargeSshPrivateKeyPem),
					StoreId:    cs.PublicId,
				},
			},
		},
		{
			name:      "valid-with-passphrase",
			projectId: prj.PublicId,
			cred: &SshPrivateKeyCredential{
				SshPrivateKeyCredential: &store.SshPrivateKeyCredential{
					Username:             "my-user",
					PrivateKey:           []byte(TestSshPrivateKeyPem),
					StoreId:              cs.PublicId,
					PrivateKeyPassphrase: []byte("passphrase"),
				},
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			ctx := context.Background()
			kkms := kms.TestKms(t, conn, wrapper)
			repo, err := NewRepository(ctx, rw, rw, kkms)
			require.NoError(err)
			require.NotNil(repo)

			got, err := repo.CreateSshPrivateKeyCredential(ctx, tt.projectId, tt.cred)
			if tt.wantErr {
				assert.Truef(errors.Match(errors.T(tt.wantErr), err), "want err: %q got: %q", tt.wantErr, err)
				assert.Nil(got)
				return
			}
			require.NoError(err)
			assertPublicId(t, globals.SshPrivateKeyCredentialPrefix, got.PublicId)
			assert.Equal(tt.cred.Username, got.Username)
			assert.Nil(got.PrivateKey)
			assert.Nil(got.PrivateKeyEncrypted)
			assert.Nil(got.PrivateKeyPassphrase)
			assert.Nil(got.PrivateKeyPassphraseEncrypted)

			// Validate private key and passphrase
			lookupCred := allocSshPrivateKeyCredential()
			lookupCred.PublicId = got.PublicId
			require.NoError(rw.LookupById(ctx, lookupCred))

			databaseWrapper, err := kkms.GetWrapper(context.Background(), tt.projectId, kms.KeyPurposeDatabase)
			require.NoError(err)
			require.NoError(lookupCred.decrypt(ctx, databaseWrapper))
			assert.Equal(tt.cred.PrivateKey, lookupCred.PrivateKey)

			assert.Empty(got.PrivateKey)
			assert.Empty(got.PrivateKeyEncrypted)
			assert.NotEmpty(got.PrivateKeyHmac)

			// Validate hmac
			hm, err := crypto.HmacSha256(ctx, tt.cred.PrivateKey, databaseWrapper, []byte(tt.cred.StoreId), nil)
			require.NoError(err)
			assert.Equal([]byte(hm), got.PrivateKeyHmac)

			// Validate passphrase
			assert.Equal(tt.cred.PrivateKeyPassphrase, lookupCred.PrivateKeyPassphrase)
			if len(tt.cred.PrivateKeyPassphrase) > 0 {
				assert.NotEmpty(got.PrivateKeyPassphraseHmac)
				hm, err := crypto.HmacSha256(ctx, tt.cred.PrivateKeyPassphrase, databaseWrapper, []byte(tt.cred.StoreId), nil)
				require.NoError(err)
				assert.Equal([]byte(hm), got.PrivateKeyPassphraseHmac)
			}

			// Validate oplog
			assert.NoError(db.TestVerifyOplog(t, rw, got.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second)))
		})
	}

	t.Run("duplicate-names", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		ctx := context.Background()
		kms := kms.TestKms(t, conn, wrapper)
		repo, err := NewRepository(ctx, rw, rw, kms)
		require.NoError(err)
		require.NotNil(repo)
		org, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		prj2 := iam.TestProject(t, iam.TestRepo(t, conn, wrapper), org.PublicId)
		require.NoError(err)

		prjCs := TestCredentialStore(t, conn, wrapper, prj.GetPublicId())
		prj2Cs := TestCredentialStore(t, conn, wrapper, prj2.GetPublicId())

		in, err := NewSshPrivateKeyCredential(ctx, prjCs.GetPublicId(), "user", credential.PrivateKey(TestSshPrivateKeyPem), WithName("my-name"), WithDescription("original"))
		assert.NoError(err)

		got, err := repo.CreateSshPrivateKeyCredential(ctx, prj.PublicId, in)
		require.NoError(err)
		assert.Equal(in.Name, got.Name)
		assert.Equal(in.Description, got.Description)

		in2, err := NewSshPrivateKeyCredential(ctx, prjCs.GetPublicId(), "user", credential.PrivateKey(TestSshPrivateKeyPem), WithName("my-name"), WithDescription("different"))
		require.NoError(err)
		got2, err := repo.CreateSshPrivateKeyCredential(ctx, prj.GetPublicId(), in2)
		assert.Truef(errors.Match(errors.T(errors.NotUnique), err), "want err code: %v got err: %v", errors.NotUnique, err)
		assert.Nil(got2)

		// Creating credential in different project should not conflict
		in3, err := NewSshPrivateKeyCredential(ctx, prj2Cs.GetPublicId(), "user", credential.PrivateKey(TestSshPrivateKeyPem), WithName("my-name"), WithDescription("different"))
		require.NoError(err)
		got3, err := repo.CreateSshPrivateKeyCredential(ctx, prj2.GetPublicId(), in3)
		require.NoError(err)
		assert.Equal(in3.Name, got3.Name)
		assert.Equal(in3.Description, got3.Description)

		assert.NotEqual(got.PublicId, got3.PublicId)
	})
}

func TestRepository_CreateJsonCredential(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))

	obj, objBytes := TestJsonObject(t)

	cs := TestCredentialStore(t, conn, wrapper, prj.PublicId)

	tests := []struct {
		name        string
		projectId   string
		cred        *JsonCredential
		wantErr     bool
		wantErrCode errors.Code
	}{
		{
			name:        "missing-store",
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
		},
		{
			name:        "missing-embedded-cred",
			cred:        &JsonCredential{},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
		},
		{
			name: "missing-project-id",
			cred: &JsonCredential{
				JsonCredential: &store.JsonCredential{
					Object:  objBytes,
					StoreId: cs.PublicId,
				},
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
		},
		{
			name:      "missing-secret",
			projectId: prj.PublicId,
			cred: &JsonCredential{
				JsonCredential: &store.JsonCredential{
					StoreId: cs.PublicId,
				},
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
		},
		{
			name:      "missing-store-id",
			projectId: prj.PublicId,
			cred: &JsonCredential{
				JsonCredential: &store.JsonCredential{
					Object: objBytes,
				},
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
		},
		{
			name:      "valid",
			projectId: prj.PublicId,
			cred: &JsonCredential{
				JsonCredential: &store.JsonCredential{
					Object:  objBytes,
					StoreId: cs.PublicId,
				},
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			ctx := context.Background()
			kkms := kms.TestKms(t, conn, wrapper)
			repo, err := NewRepository(ctx, rw, rw, kkms)
			require.NoError(err)
			require.NotNil(repo)

			got, err := repo.CreateJsonCredential(ctx, tt.projectId, tt.cred)
			if tt.wantErr {
				assert.Truef(errors.Match(errors.T(tt.wantErr), err), "want err: %q got: %q", tt.wantErr, err)
				assert.Nil(got)
				return
			}
			require.NoError(err)
			assertPublicId(t, globals.JsonCredentialPrefix, got.PublicId)
			assert.Nil(got.Object)
			assert.Nil(got.ObjectEncrypted)

			// Validate secret
			lookupCred := allocJsonCredential()
			lookupCred.PublicId = got.PublicId
			require.NoError(rw.LookupById(ctx, lookupCred))

			databaseWrapper, err := kkms.GetWrapper(context.Background(), tt.projectId, kms.KeyPurposeDatabase)
			require.NoError(err)
			require.NoError(lookupCred.decrypt(ctx, databaseWrapper))
			assert.Equal(tt.cred.Object, lookupCred.Object)

			assert.Empty(got.Object)
			assert.Empty(got.ObjectEncrypted)
			assert.NotEmpty(got.ObjectHmac)

			// Validate hmac
			hm, err := crypto.HmacSha256(ctx, tt.cred.Object, databaseWrapper, []byte(tt.cred.StoreId), nil)
			require.NoError(err)
			assert.Equal([]byte(hm), got.ObjectHmac)

			// Validate oplog
			assert.NoError(db.TestVerifyOplog(t, rw, got.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second)))
		})
	}

	t.Run("duplicate-names", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		ctx := context.Background()
		kms := kms.TestKms(t, conn, wrapper)
		repo, err := NewRepository(ctx, rw, rw, kms)
		require.NoError(err)
		require.NotNil(repo)
		org, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		prj2 := iam.TestProject(t, iam.TestRepo(t, conn, wrapper), org.PublicId)
		require.NoError(err)

		prjCs := TestCredentialStore(t, conn, wrapper, prj.GetPublicId())
		prj2Cs := TestCredentialStore(t, conn, wrapper, prj2.GetPublicId())

		in, err := NewJsonCredential(ctx, prjCs.GetPublicId(), obj, WithName("my-name"), WithDescription("original"))
		assert.NoError(err)

		got, err := repo.CreateJsonCredential(ctx, prj.PublicId, in)
		require.NoError(err)
		assert.Equal(in.Name, got.Name)
		assert.Equal(in.Description, got.Description)

		in2, err := NewJsonCredential(ctx, prjCs.GetPublicId(), obj, WithName("my-name"), WithDescription("different"))
		require.NoError(err)
		got2, err := repo.CreateJsonCredential(ctx, prj.GetPublicId(), in2)
		assert.Truef(errors.Match(errors.T(errors.NotUnique), err), "want err code: %v got err: %v", errors.NotUnique, err)
		assert.Nil(got2)

		// Creating credential in different scope should not conflict
		in3, err := NewJsonCredential(ctx, prj2Cs.GetPublicId(), obj, WithName("my-name"), WithDescription("different"))
		require.NoError(err)
		got3, err := repo.CreateJsonCredential(ctx, org.GetPublicId(), in3)
		require.NoError(err)
		assert.Equal(in3.Name, got3.Name)
		assert.Equal(in3.Description, got3.Description)

		assert.NotEqual(got.PublicId, got3.PublicId)
	})
}

func TestRepository_LookupCredential(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)

	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	store := TestCredentialStore(t, conn, wrapper, prj.PublicId)
	upCred := TestUsernamePasswordCredential(t, conn, wrapper, "username", "password", store.PublicId, prj.PublicId)
	updCred := TestUsernamePasswordDomainCredential(t, conn, wrapper, "username", "password", "domain.com", store.PublicId, prj.PublicId)
	pCred := TestPasswordCredential(t, conn, wrapper, "password", store.PublicId, prj.PublicId)
	spkCred := TestSshPrivateKeyCredential(t, conn, wrapper, "username", TestSshPrivateKeyPem, store.PublicId, prj.PublicId)
	spkCredWithPass := TestSshPrivateKeyCredential(t, conn, wrapper, "username", string(testdata.PEMEncryptedKeys[0].PEMBytes),
		store.PublicId, prj.PublicId, WithPrivateKeyPassphrase([]byte(testdata.PEMEncryptedKeys[0].EncryptionKey)))

	obj, _ := TestJsonObject(t)

	jsonCred := TestJsonCredential(t, conn, wrapper, store.PublicId, prj.PublicId, obj)

	tests := []struct {
		name    string
		id      string
		want    credential.Static
		wantErr errors.Code
	}{
		{
			name: "up-valid",
			id:   upCred.GetPublicId(),
			want: upCred,
		},
		{
			name: "upd-valid",
			id:   updCred.GetPublicId(),
			want: updCred,
		},
		{
			name: "p-valid",
			id:   pCred.GetPublicId(),
			want: pCred,
		},
		{
			name: "spk-valid",
			id:   spkCred.GetPublicId(),
			want: spkCred,
		},
		{
			name: "spk-valid-with-passphrase",
			id:   spkCredWithPass.GetPublicId(),
			want: spkCredWithPass,
		},
		{
			name: "json-valid",
			id:   jsonCred.GetPublicId(),
			want: jsonCred,
		},
		{
			name:    "empty-public-id",
			id:      "",
			wantErr: errors.InvalidParameter,
		},
		{
			name: "not-found",
			id:   "cred_fake",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			ctx := context.Background()
			kms := kms.TestKms(t, conn, wrapper)
			repo, err := NewRepository(ctx, rw, rw, kms)
			assert.NoError(err)
			require.NotNil(repo)

			got, err := repo.LookupCredential(ctx, tt.id)
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

			require.NotNil(got)
			switch v := got.(type) {
			case *UsernamePasswordCredential:
				assert.Empty(v.Password)
				assert.Empty(v.CtPassword)
				assert.NotEmpty(v.PasswordHmac)
			case *UsernamePasswordDomainCredential:
				assert.Empty(v.Password)
				assert.Empty(v.CtPassword)
				assert.NotEmpty(v.PasswordHmac)
			case *PasswordCredential:
				assert.Empty(v.Password)
				assert.Empty(v.CtPassword)
				assert.NotEmpty(v.PasswordHmac)
			case *SshPrivateKeyCredential:
				assert.Empty(v.PrivateKey)
				assert.Empty(v.PrivateKeyEncrypted)
				assert.NotEmpty(v.PrivateKeyHmac)
				want, ok := tt.want.(*SshPrivateKeyCredential)
				require.True(ok)
				assert.Empty(v.PrivateKeyPassphrase)
				assert.Empty(v.PrivateKeyPassphraseEncrypted)
				if len(want.PrivateKeyPassphrase) > 0 {
					assert.NotEmpty(v.PrivateKeyPassphraseHmac)
				}
			case *JsonCredential:
				assert.Empty(v.Object)
				assert.Empty(v.ObjectEncrypted)
				assert.NotEmpty(v.ObjectHmac)
			default:
				require.Fail("unknown type")
			}
		})
	}
}

func TestRepository_ListCredentials(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)

	defaultLimit := 5
	total := 40
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	store := TestCredentialStore(t, conn, wrapper, prj.GetPublicId())
	TestUsernamePasswordCredentials(t, conn, wrapper, "user", "pass", store.GetPublicId(), prj.GetPublicId(), total/4)
	TestUsernamePasswordDomainCredentials(t, conn, wrapper, "user", "pass", "domain.com", store.GetPublicId(), prj.GetPublicId(), total/4)
	TestPasswordCredentials(t, conn, wrapper, "pass", store.GetPublicId(), prj.GetPublicId(), total/4)
	TestSshPrivateKeyCredentials(t, conn, wrapper, "user", TestSshPrivateKeyPem, store.GetPublicId(), prj.GetPublicId(), total/4)

	obj, _ := TestJsonObject(t)

	TestJsonCredentials(t, conn, wrapper, store.GetPublicId(), prj.GetPublicId(), obj, total/4)

	type args struct {
		storeId string
		opt     []credential.Option
	}
	tests := []struct {
		name    string
		args    args
		wantCnt int
	}{
		{
			name: "default-limit",
			args: args{
				storeId: store.PublicId,
			},
			wantCnt: defaultLimit,
		},
		{
			name: "custom-limit",
			args: args{
				storeId: store.PublicId,
				opt:     []credential.Option{credential.WithLimit(3)},
			},
			wantCnt: 3,
		},
		{
			name: "bad-store",
			args: args{
				storeId: "bad-id",
			},
			wantCnt: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(context.Background(), rw, rw, kms)
			assert.NoError(err)
			require.NotNil(repo)
			repo.defaultLimit = defaultLimit

			got, ttime, err := repo.ListCredentials(context.Background(), tt.args.storeId, tt.args.opt...)
			require.NoError(err)
			assert.Equal(tt.wantCnt, len(got))
			// Transaction timestamp should be within ~10 seconds of now
			assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
			assert.True(time.Now().After(ttime.Add(-10 * time.Second)))

			// Validate only hmac values are returned
			for _, c := range got {
				switch v := c.(type) {
				case *UsernamePasswordCredential:
					assert.Empty(v.Password)
					assert.Empty(v.CtPassword)
					assert.NotEmpty(v.PasswordHmac)
				case *UsernamePasswordDomainCredential:
					assert.Empty(v.Password)
					assert.Empty(v.CtPassword)
					assert.NotEmpty(v.PasswordHmac)
				case *PasswordCredential:
					assert.Empty(v.Password)
					assert.Empty(v.CtPassword)
					assert.NotEmpty(v.PasswordHmac)
				case *SshPrivateKeyCredential:
					assert.Empty(v.PrivateKey)
					assert.Empty(v.PrivateKeyEncrypted)
					assert.NotEmpty(v.PrivateKeyHmac)
				case *JsonCredential:
					assert.Empty(v.Object)
					assert.Empty(v.ObjectEncrypted)
					assert.NotEmpty(v.ObjectHmac)
				default:
					require.Fail("unknown type")
				}
			}
		})
	}
}

func TestRepository_ListCredentials_Pagination(t *testing.T) {
	t.Parallel()
	assert, require := assert.New(t), require.New(t)
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	store := TestCredentialStore(t, conn, wrapper, prj.GetPublicId())
	obj, _ := TestJsonObject(t)
	_ = TestJsonCredentials(t, conn, wrapper, store.GetPublicId(), prj.GetPublicId(), obj, 2)
	_ = TestSshPrivateKeyCredentials(t, conn, wrapper, "username", TestSshPrivateKeyPem, store.GetPublicId(), prj.GetPublicId(), 2)
	_ = TestUsernamePasswordCredentials(t, conn, wrapper, "username", "testpassword", store.GetPublicId(), prj.GetPublicId(), 2)
	_ = TestUsernamePasswordDomainCredentials(t, conn, wrapper, "username", "testpassword", "domain.com", store.GetPublicId(), prj.GetPublicId(), 1)
	_ = TestPasswordCredentials(t, conn, wrapper, "testpassword", store.GetPublicId(), prj.GetPublicId(), 1)

	repo, err := NewRepository(ctx, rw, rw, kms)
	require.NoError(err)
	require.NotNil(repo)

	page1, ttime, err := repo.ListCredentials(ctx, store.GetPublicId(), credential.WithLimit(2))
	require.NoError(err)
	require.Len(page1, 2)
	// Transaction timestamp should be within ~10 seconds of now
	assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
	assert.True(time.Now().After(ttime.Add(-10 * time.Second)))

	page2, ttime, err := repo.ListCredentials(ctx, store.GetPublicId(), credential.WithLimit(2), credential.WithStartPageAfterItem(page1[1]))
	require.NoError(err)
	require.Len(page2, 2)
	pages := page1
	for _, item := range pages {
		assert.NotEqual(item.GetPublicId(), page2[0].GetPublicId())
		assert.NotEqual(item.GetPublicId(), page2[1].GetPublicId())
	}
	assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
	assert.True(time.Now().After(ttime.Add(-10 * time.Second)))

	page3, ttime, err := repo.ListCredentials(ctx, store.GetPublicId(), credential.WithLimit(2), credential.WithStartPageAfterItem(page2[1]))
	require.NoError(err)
	require.Len(page3, 2)
	pages = append(pages, page2...)
	for _, item := range pages {
		assert.NotEqual(item.GetPublicId(), page3[0].GetPublicId())
		assert.NotEqual(item.GetPublicId(), page3[1].GetPublicId())
	}
	assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
	assert.True(time.Now().After(ttime.Add(-10 * time.Second)))

	page4, ttime, err := repo.ListCredentials(ctx, store.GetPublicId(), credential.WithLimit(2), credential.WithStartPageAfterItem(page3[1]))
	require.NoError(err)
	require.Len(page4, 2)
	pages = append(pages, page3...)
	for _, item := range pages {
		assert.NotEqual(item.GetPublicId(), page4[0].GetPublicId())
		assert.NotEqual(item.GetPublicId(), page4[1].GetPublicId())
	}
	assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
	assert.True(time.Now().After(ttime.Add(-10 * time.Second)))

	page5, ttime, err := repo.ListCredentials(ctx, store.GetPublicId(), credential.WithLimit(2), credential.WithStartPageAfterItem(page4[1]))
	require.NoError(err)
	require.Empty(page5)
	assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
	assert.True(time.Now().After(ttime.Add(-10 * time.Second)))
}

func TestRepository_ListCredentialsRefresh(t *testing.T) {
	t.Parallel()
	assert, require := assert.New(t), require.New(t)
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	currTime := time.Now()
	store := TestCredentialStore(t, conn, wrapper, prj.GetPublicId())
	obj, _ := TestJsonObject(t)
	_ = TestJsonCredentials(t, conn, wrapper, store.GetPublicId(), prj.GetPublicId(), obj, 2)
	_ = TestSshPrivateKeyCredentials(t, conn, wrapper, "username", TestSshPrivateKeyPem, store.GetPublicId(), prj.GetPublicId(), 2)
	_ = TestUsernamePasswordCredentials(t, conn, wrapper, "username", "testpassword", store.GetPublicId(), prj.GetPublicId(), 2)
	_ = TestUsernamePasswordDomainCredentials(t, conn, wrapper, "username", "testpassword", "domain.com", store.GetPublicId(), prj.GetPublicId(), 1)

	repo, err := NewRepository(ctx, rw, rw, kms)
	require.NoError(err)
	require.NotNil(repo)

	page1, ttime, err := repo.ListCredentialsRefresh(ctx, store.GetPublicId(), currTime, credential.WithLimit(2))
	require.NoError(err)
	require.Len(page1, 2)
	// Transaction timestamp should be within ~10 seconds of now
	assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
	assert.True(time.Now().After(ttime.Add(-10 * time.Second)))

	page2, ttime, err := repo.ListCredentialsRefresh(ctx, store.GetPublicId(), currTime, credential.WithLimit(2), credential.WithStartPageAfterItem(page1[1]))
	require.NoError(err)
	require.Len(page2, 2)
	pages := page1
	for _, item := range pages {
		assert.NotEqual(item.GetPublicId(), page2[0].GetPublicId())
		assert.NotEqual(item.GetPublicId(), page2[1].GetPublicId())
	}
	assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
	assert.True(time.Now().After(ttime.Add(-10 * time.Second)))

	page3, ttime, err := repo.ListCredentialsRefresh(ctx, store.GetPublicId(), currTime, credential.WithLimit(2), credential.WithStartPageAfterItem(page2[1]))
	require.NoError(err)
	require.Len(page3, 2)
	pages = append(pages, page2...)
	for _, item := range pages {
		assert.NotEqual(item.GetPublicId(), page3[0].GetPublicId())
		assert.NotEqual(item.GetPublicId(), page3[1].GetPublicId())
	}
	assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
	assert.True(time.Now().After(ttime.Add(-10 * time.Second)))

	page4, ttime, err := repo.ListCredentialsRefresh(ctx, store.GetPublicId(), currTime, credential.WithLimit(2), credential.WithStartPageAfterItem(page3[1]))
	require.NoError(err)
	require.Len(page4, 1)
	pages = append(pages, page3...)
	for _, item := range pages {
		assert.NotEqual(item.GetPublicId(), page4[0].GetPublicId())
	}
	assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
	assert.True(time.Now().After(ttime.Add(-10 * time.Second)))

	page5, ttime, err := repo.ListCredentialsRefresh(ctx, store.GetPublicId(), currTime, credential.WithLimit(2), credential.WithStartPageAfterItem(page4[0]))
	require.NoError(err)
	require.Empty(page5)
	assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
	assert.True(time.Now().After(ttime.Add(-10 * time.Second)))
}

func TestRepository_DeleteCredential(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)

	kms := kms.TestKms(t, conn, wrapper)
	iam.TestRepo(t, conn, wrapper)

	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	store := TestCredentialStore(t, conn, wrapper, prj.PublicId)
	upCred := TestUsernamePasswordCredential(t, conn, wrapper, "user", "pass", store.GetPublicId(), prj.GetPublicId())
	spkCred := TestSshPrivateKeyCredential(t, conn, wrapper, "user", TestSshPrivateKeyPem, store.GetPublicId(), prj.GetPublicId())

	obj, _ := TestJsonObject(t)

	jsonCred := TestJsonCredential(t, conn, wrapper, store.PublicId, prj.PublicId, obj)

	tests := []struct {
		name        string
		in          string
		want        int
		wantErr     bool
		wantErrCode errors.Code
	}{
		{
			name:        "With no public id",
			wantErr:     true,
			wantErrCode: errors.InvalidPublicId,
		},
		{
			name: "With non existing account id",
			in:   "cred_fakeid",
			want: 0,
		},
		{
			name: "With existing username-password id",
			in:   upCred.GetPublicId(),
			want: 1,
		},
		{
			name: "With existing ssh private key id",
			in:   spkCred.GetPublicId(),
			want: 1,
		},
		{
			name: "with existing json id",
			in:   jsonCred.GetPublicId(),
			want: 1,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(context.Background(), rw, rw, kms)
			assert.NoError(err)
			require.NotNil(repo)
			got, err := repo.DeleteCredential(context.Background(), prj.GetPublicId(), tt.in)
			if tt.wantErr {
				assert.Truef(errors.Match(errors.T(tt.wantErrCode), err), "Unexpected error %s", err)
				return
			}
			require.NoError(err)
			assert.EqualValues(tt.want, got)
		})
	}
}

func TestRepository_UpdateUsernamePasswordCredential(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)

	changeName := func(n string) func(credential *UsernamePasswordCredential) *UsernamePasswordCredential {
		return func(c *UsernamePasswordCredential) *UsernamePasswordCredential {
			c.Name = n
			return c
		}
	}

	changeDescription := func(d string) func(*UsernamePasswordCredential) *UsernamePasswordCredential {
		return func(c *UsernamePasswordCredential) *UsernamePasswordCredential {
			c.Description = d
			return c
		}
	}

	makeNil := func() func(*UsernamePasswordCredential) *UsernamePasswordCredential {
		return func(_ *UsernamePasswordCredential) *UsernamePasswordCredential {
			return nil
		}
	}

	makeEmbeddedNil := func() func(*UsernamePasswordCredential) *UsernamePasswordCredential {
		return func(_ *UsernamePasswordCredential) *UsernamePasswordCredential {
			return &UsernamePasswordCredential{}
		}
	}

	setPublicId := func(n string) func(*UsernamePasswordCredential) *UsernamePasswordCredential {
		return func(c *UsernamePasswordCredential) *UsernamePasswordCredential {
			c.PublicId = n
			return c
		}
	}

	deleteStoreId := func() func(*UsernamePasswordCredential) *UsernamePasswordCredential {
		return func(c *UsernamePasswordCredential) *UsernamePasswordCredential {
			c.StoreId = ""
			return c
		}
	}

	deleteVersion := func() func(*UsernamePasswordCredential) *UsernamePasswordCredential {
		return func(c *UsernamePasswordCredential) *UsernamePasswordCredential {
			c.Version = 0
			return c
		}
	}

	changeUser := func(n string) func(credential *UsernamePasswordCredential) *UsernamePasswordCredential {
		return func(c *UsernamePasswordCredential) *UsernamePasswordCredential {
			c.Username = n
			return c
		}
	}

	changePassword := func(d string) func(*UsernamePasswordCredential) *UsernamePasswordCredential {
		return func(c *UsernamePasswordCredential) *UsernamePasswordCredential {
			c.Password = []byte(d)
			return c
		}
	}

	combine := func(fns ...func(cs *UsernamePasswordCredential) *UsernamePasswordCredential) func(*UsernamePasswordCredential) *UsernamePasswordCredential {
		return func(c *UsernamePasswordCredential) *UsernamePasswordCredential {
			for _, fn := range fns {
				c = fn(c)
			}
			return c
		}
	}

	tests := []struct {
		name      string
		orig      *UsernamePasswordCredential
		chgFn     func(*UsernamePasswordCredential) *UsernamePasswordCredential
		masks     []string
		want      *UsernamePasswordCredential
		wantCount int
		wantErr   errors.Code
	}{
		{
			name: "nil-credential",
			orig: &UsernamePasswordCredential{
				UsernamePasswordCredential: &store.UsernamePasswordCredential{
					Username: "user",
					Password: []byte("pass"),
				},
			},
			chgFn:   makeNil(),
			masks:   []string{"Name", "Description"},
			wantErr: errors.InvalidParameter,
		},
		{
			name: "nil-embedded-credential",
			orig: &UsernamePasswordCredential{
				UsernamePasswordCredential: &store.UsernamePasswordCredential{
					Username: "user",
					Password: []byte("pass"),
				},
			},
			chgFn:   makeEmbeddedNil(),
			masks:   []string{"Name", "Description"},
			wantErr: errors.InvalidParameter,
		},
		{
			name: "no-public-id",
			orig: &UsernamePasswordCredential{
				UsernamePasswordCredential: &store.UsernamePasswordCredential{
					Username: "user",
					Password: []byte("pass"),
				},
			},
			chgFn:   setPublicId(""),
			masks:   []string{"Name", "Description"},
			wantErr: errors.InvalidPublicId,
		},
		{
			name: "no-store-id",
			orig: &UsernamePasswordCredential{
				UsernamePasswordCredential: &store.UsernamePasswordCredential{
					Username: "user",
					Password: []byte("pass"),
				},
			},
			chgFn:   deleteStoreId(),
			masks:   []string{"Name", "Description"},
			wantErr: errors.InvalidParameter,
		},
		{
			name: "no-version",
			orig: &UsernamePasswordCredential{
				UsernamePasswordCredential: &store.UsernamePasswordCredential{
					Username: "user",
					Password: []byte("pass"),
				},
			},
			chgFn:   deleteVersion(),
			masks:   []string{"Name", "Description"},
			wantErr: errors.InvalidParameter,
		},
		{
			name: "updating-non-existent-credential",
			orig: &UsernamePasswordCredential{
				UsernamePasswordCredential: &store.UsernamePasswordCredential{
					Name:     "test-name-repo",
					Username: "user",
					Password: []byte("pass"),
				},
			},
			chgFn:   combine(setPublicId("abcd_OOOOOOOOOO"), changeName("test-update-name-repo")),
			masks:   []string{"Name"},
			wantErr: errors.RecordNotFound,
		},
		{
			name: "empty-field-mask",
			orig: &UsernamePasswordCredential{
				UsernamePasswordCredential: &store.UsernamePasswordCredential{
					Name:     "test-name-repo",
					Username: "user",
					Password: []byte("pass"),
				},
			},
			chgFn:   changeName("test-update-name-repo"),
			wantErr: errors.EmptyFieldMask,
		},
		{
			name: "read-only-fields-in-field-mask",
			orig: &UsernamePasswordCredential{
				UsernamePasswordCredential: &store.UsernamePasswordCredential{
					Name:     "test-name-repo",
					Username: "user",
					Password: []byte("pass"),
				},
			},
			chgFn:   changeName("test-update-name-repo"),
			masks:   []string{"PublicId", "CreateTime", "UpdateTime", "ProjectId"},
			wantErr: errors.InvalidFieldMask,
		},
		{
			name: "unknown-field-in-field-mask",
			orig: &UsernamePasswordCredential{
				UsernamePasswordCredential: &store.UsernamePasswordCredential{
					Name:     "test-name-repo",
					Username: "user",
					Password: []byte("pass"),
				},
			},
			chgFn:   changeName("test-update-name-repo"),
			masks:   []string{"Bilbo"},
			wantErr: errors.InvalidFieldMask,
		},
		{
			name: "change-name",
			orig: &UsernamePasswordCredential{
				UsernamePasswordCredential: &store.UsernamePasswordCredential{
					Name:     "test-name-repo",
					Username: "user",
					Password: []byte("pass"),
				},
			},
			chgFn: changeName("test-update-name-repo"),
			masks: []string{"Name"},
			want: &UsernamePasswordCredential{
				UsernamePasswordCredential: &store.UsernamePasswordCredential{
					Name:     "test-update-name-repo",
					Username: "user",
					Password: []byte("pass"),
				},
			},
			wantCount: 1,
		},
		{
			name: "change-description",
			orig: &UsernamePasswordCredential{
				UsernamePasswordCredential: &store.UsernamePasswordCredential{
					Description: "test-description-repo",
					Username:    "user",
					Password:    []byte("pass"),
				},
			},
			chgFn: changeDescription("test-update-description-repo"),
			masks: []string{"Description"},
			want: &UsernamePasswordCredential{
				UsernamePasswordCredential: &store.UsernamePasswordCredential{
					Description: "test-update-description-repo",
					Username:    "user",
					Password:    []byte("pass"),
				},
			},
			wantCount: 1,
		},
		{
			name: "change-name-and-description",
			orig: &UsernamePasswordCredential{
				UsernamePasswordCredential: &store.UsernamePasswordCredential{
					Name:        "test-name-repo",
					Description: "test-description-repo",
					Username:    "user",
					Password:    []byte("pass"),
				},
			},
			chgFn: combine(changeDescription("test-update-description-repo"), changeName("test-update-name-repo")),
			masks: []string{"Name", "Description"},
			want: &UsernamePasswordCredential{
				UsernamePasswordCredential: &store.UsernamePasswordCredential{
					Name:        "test-update-name-repo",
					Description: "test-update-description-repo",
					Username:    "user",
					Password:    []byte("pass"),
				},
			},
			wantCount: 1,
		},
		{
			name: "change-username",
			orig: &UsernamePasswordCredential{
				UsernamePasswordCredential: &store.UsernamePasswordCredential{
					Username: "user",
					Password: []byte("pass"),
				},
			},
			chgFn: changeUser("test-update-user"),
			masks: []string{"Username"},
			want: &UsernamePasswordCredential{
				UsernamePasswordCredential: &store.UsernamePasswordCredential{
					Username: "test-update-user",
					Password: []byte("pass"),
				},
			},
			wantCount: 1,
		},
		{
			name: "change-password",
			orig: &UsernamePasswordCredential{
				UsernamePasswordCredential: &store.UsernamePasswordCredential{
					Username: "user",
					Password: []byte("pass"),
				},
			},
			chgFn: changePassword("test-update-pass"),
			masks: []string{"Password"},
			want: &UsernamePasswordCredential{
				UsernamePasswordCredential: &store.UsernamePasswordCredential{
					Username: "user",
					Password: []byte("test-update-pass"),
				},
			},
			wantCount: 1,
		},
		{
			name: "change-username-and-password",
			orig: &UsernamePasswordCredential{
				UsernamePasswordCredential: &store.UsernamePasswordCredential{
					Username: "user",
					Password: []byte("pass"),
				},
			},
			chgFn: combine(changeUser("test-update-user"), changePassword("test-update-pass")),
			masks: []string{"Username", "Password"},
			want: &UsernamePasswordCredential{
				UsernamePasswordCredential: &store.UsernamePasswordCredential{
					Username: "test-update-user",
					Password: []byte("test-update-pass"),
				},
			},
			wantCount: 1,
		},
		{
			name: "do-not-delete-password",
			orig: &UsernamePasswordCredential{
				UsernamePasswordCredential: &store.UsernamePasswordCredential{
					Username: "user",
					Password: []byte("pass"),
				},
			},
			masks: []string{"Username"},
			chgFn: combine(changeUser("test-new-user"), changePassword("")),
			want: &UsernamePasswordCredential{
				UsernamePasswordCredential: &store.UsernamePasswordCredential{
					Username: "test-new-user",
					Password: []byte("pass"),
				},
			},
			wantCount: 1,
		},
		{
			name: "do-not-delete-username",
			orig: &UsernamePasswordCredential{
				UsernamePasswordCredential: &store.UsernamePasswordCredential{
					Username: "user",
					Password: []byte("pass"),
				},
			},
			masks: []string{"Password"},
			chgFn: combine(changeUser(""), changePassword("test-new-password")),
			want: &UsernamePasswordCredential{
				UsernamePasswordCredential: &store.UsernamePasswordCredential{
					Username: "user",
					Password: []byte("test-new-password"),
				},
			},
			wantCount: 1,
		},
		{
			name: "delete-name",
			orig: &UsernamePasswordCredential{
				UsernamePasswordCredential: &store.UsernamePasswordCredential{
					Name:        "test-name-repo",
					Description: "test-description-repo",
					Username:    "user",
					Password:    []byte("pass"),
				},
			},
			masks: []string{"Name"},
			chgFn: combine(changeDescription("test-update-description-repo"), changeName("")),
			want: &UsernamePasswordCredential{
				UsernamePasswordCredential: &store.UsernamePasswordCredential{
					Description: "test-description-repo",
					Username:    "user",
					Password:    []byte("pass"),
				},
			},
			wantCount: 1,
		},
		{
			name: "delete-description",
			orig: &UsernamePasswordCredential{
				UsernamePasswordCredential: &store.UsernamePasswordCredential{
					Name:        "test-name-repo",
					Description: "test-description-repo",
					Username:    "user",
					Password:    []byte("pass"),
				},
			},
			masks: []string{"Description"},
			chgFn: combine(changeDescription(""), changeName("test-update-name-repo")),
			want: &UsernamePasswordCredential{
				UsernamePasswordCredential: &store.UsernamePasswordCredential{
					Name:     "test-name-repo",
					Username: "user",
					Password: []byte("pass"),
				},
			},
			wantCount: 1,
		},
		{
			name: "do-not-delete-name",
			orig: &UsernamePasswordCredential{
				UsernamePasswordCredential: &store.UsernamePasswordCredential{
					Name:        "test-name-repo",
					Description: "test-description-repo",
					Username:    "user",
					Password:    []byte("pass"),
				},
			},
			masks: []string{"Description"},
			chgFn: combine(changeDescription("test-update-description-repo"), changeName("")),
			want: &UsernamePasswordCredential{
				UsernamePasswordCredential: &store.UsernamePasswordCredential{
					Name:        "test-name-repo",
					Description: "test-update-description-repo",
					Username:    "user",
					Password:    []byte("pass"),
				},
			},
			wantCount: 1,
		},
		{
			name: "do-not-delete-description",
			orig: &UsernamePasswordCredential{
				UsernamePasswordCredential: &store.UsernamePasswordCredential{
					Name:        "test-name-repo",
					Description: "test-description-repo",
					Username:    "user",
					Password:    []byte("pass"),
				},
			},
			masks: []string{"Name"},
			chgFn: combine(changeDescription(""), changeName("test-update-name-repo")),
			want: &UsernamePasswordCredential{
				UsernamePasswordCredential: &store.UsernamePasswordCredential{
					Name:        "test-update-name-repo",
					Description: "test-description-repo",
					Username:    "user",
					Password:    []byte("pass"),
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
			kkms := kms.TestKms(t, conn, wrapper)
			repo, err := NewRepository(ctx, rw, rw, kkms)
			assert.NoError(err)
			require.NotNil(repo)

			_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
			store := TestCredentialStore(t, conn, wrapper, prj.GetPublicId())
			tt.orig.StoreId = store.PublicId

			orig, err := repo.CreateUsernamePasswordCredential(ctx, prj.GetPublicId(), tt.orig)
			assert.NoError(err)
			require.NotNil(orig)

			if tt.chgFn != nil {
				orig = tt.chgFn(orig)
			}
			var version uint32
			if orig != nil {
				version = orig.GetVersion()
			}
			got, gotCount, err := repo.UpdateUsernamePasswordCredential(ctx, prj.GetPublicId(), orig, version, tt.masks)
			if tt.wantErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantErr), err), "want err: %q got: %q", tt.wantErr, err)
				assert.Equal(tt.wantCount, gotCount, "row count")
				assert.Nil(got)
				return
			}
			assert.NoError(err)
			assert.Empty(tt.orig.PublicId)
			require.NotNil(got)
			assertPublicId(t, globals.UsernamePasswordCredentialPrefix, got.PublicId)
			assert.Equal(tt.wantCount, gotCount, "row count")
			assert.NotSame(tt.orig, got)
			assert.Equal(tt.orig.StoreId, got.StoreId)
			underlyingDB, err := conn.SqlDB(ctx)
			require.NoError(err)
			dbassert := dbassert.New(t, underlyingDB)
			if tt.want.Name == "" {
				got := got.clone()
				dbassert.IsNull(got, "name")
			} else {
				assert.Equal(tt.want.Name, got.Name)
			}

			if tt.want.Description == "" {
				got := got.clone()
				dbassert.IsNull(got, "description")
			} else {
				assert.Equal(tt.want.Description, got.Description)
			}

			assert.Equal(tt.want.Username, got.Username)

			// Validate only passwordHmac is returned
			assert.Empty(got.Password)
			assert.Empty(got.CtPassword)
			assert.NotEmpty(got.PasswordHmac)

			// Validate hmac
			databaseWrapper, err := kkms.GetWrapper(context.Background(), prj.GetPublicId(), kms.KeyPurposeDatabase)
			require.NoError(err)
			hm, err := crypto.HmacSha256(ctx, tt.want.Password, databaseWrapper, []byte(store.GetPublicId()), nil, crypto.WithEd25519())
			require.NoError(err)
			assert.Equal([]byte(hm), got.PasswordHmac)

			if tt.wantCount > 0 {
				assert.NoError(db.TestVerifyOplog(t, rw, got.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second)))
			}
		})
	}
}

func TestRepository_UpdateUsernamePasswordDomainCredential(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)

	changeName := func(n string) func(credential *UsernamePasswordDomainCredential) *UsernamePasswordDomainCredential {
		return func(c *UsernamePasswordDomainCredential) *UsernamePasswordDomainCredential {
			c.Name = n
			return c
		}
	}

	changeDescription := func(d string) func(*UsernamePasswordDomainCredential) *UsernamePasswordDomainCredential {
		return func(c *UsernamePasswordDomainCredential) *UsernamePasswordDomainCredential {
			c.Description = d
			return c
		}
	}

	makeNil := func() func(*UsernamePasswordDomainCredential) *UsernamePasswordDomainCredential {
		return func(_ *UsernamePasswordDomainCredential) *UsernamePasswordDomainCredential {
			return nil
		}
	}

	makeEmbeddedNil := func() func(*UsernamePasswordDomainCredential) *UsernamePasswordDomainCredential {
		return func(_ *UsernamePasswordDomainCredential) *UsernamePasswordDomainCredential {
			return &UsernamePasswordDomainCredential{}
		}
	}

	setPublicId := func(n string) func(*UsernamePasswordDomainCredential) *UsernamePasswordDomainCredential {
		return func(c *UsernamePasswordDomainCredential) *UsernamePasswordDomainCredential {
			c.PublicId = n
			return c
		}
	}

	deleteStoreId := func() func(*UsernamePasswordDomainCredential) *UsernamePasswordDomainCredential {
		return func(c *UsernamePasswordDomainCredential) *UsernamePasswordDomainCredential {
			c.StoreId = ""
			return c
		}
	}

	deleteVersion := func() func(*UsernamePasswordDomainCredential) *UsernamePasswordDomainCredential {
		return func(c *UsernamePasswordDomainCredential) *UsernamePasswordDomainCredential {
			c.Version = 0
			return c
		}
	}

	changeUser := func(n string) func(credential *UsernamePasswordDomainCredential) *UsernamePasswordDomainCredential {
		return func(c *UsernamePasswordDomainCredential) *UsernamePasswordDomainCredential {
			c.Username = n
			return c
		}
	}

	changePassword := func(d string) func(*UsernamePasswordDomainCredential) *UsernamePasswordDomainCredential {
		return func(c *UsernamePasswordDomainCredential) *UsernamePasswordDomainCredential {
			c.Password = []byte(d)
			return c
		}
	}

	changeDomain := func(d string) func(credential *UsernamePasswordDomainCredential) *UsernamePasswordDomainCredential {
		return func(c *UsernamePasswordDomainCredential) *UsernamePasswordDomainCredential {
			c.Domain = d
			return c
		}
	}

	combine := func(fns ...func(cs *UsernamePasswordDomainCredential) *UsernamePasswordDomainCredential) func(*UsernamePasswordDomainCredential) *UsernamePasswordDomainCredential {
		return func(c *UsernamePasswordDomainCredential) *UsernamePasswordDomainCredential {
			for _, fn := range fns {
				c = fn(c)
			}
			return c
		}
	}

	tests := []struct {
		name      string
		orig      *UsernamePasswordDomainCredential
		chgFn     func(*UsernamePasswordDomainCredential) *UsernamePasswordDomainCredential
		masks     []string
		want      *UsernamePasswordDomainCredential
		wantCount int
		wantErr   errors.Code
	}{
		{
			name: "nil-credential",
			orig: &UsernamePasswordDomainCredential{
				UsernamePasswordDomainCredential: &store.UsernamePasswordDomainCredential{
					Username: "user",
					Password: []byte("pass"),
					Domain:   "domain.com",
				},
			},
			chgFn:   makeNil(),
			masks:   []string{"Name", "Description"},
			wantErr: errors.InvalidParameter,
		},
		{
			name: "nil-embedded-credential",
			orig: &UsernamePasswordDomainCredential{
				UsernamePasswordDomainCredential: &store.UsernamePasswordDomainCredential{
					Username: "user",
					Password: []byte("pass"),
					Domain:   "domain.com",
				},
			},
			chgFn:   makeEmbeddedNil(),
			masks:   []string{"Name", "Description"},
			wantErr: errors.InvalidParameter,
		},
		{
			name: "no-public-id",
			orig: &UsernamePasswordDomainCredential{
				UsernamePasswordDomainCredential: &store.UsernamePasswordDomainCredential{
					Username: "user",
					Password: []byte("pass"),
					Domain:   "domain.com",
				},
			},
			chgFn:   setPublicId(""),
			masks:   []string{"Name", "Description"},
			wantErr: errors.InvalidPublicId,
		},
		{
			name: "no-store-id",
			orig: &UsernamePasswordDomainCredential{
				UsernamePasswordDomainCredential: &store.UsernamePasswordDomainCredential{
					Username: "user",
					Password: []byte("pass"),
					Domain:   "domain.com",
				},
			},
			chgFn:   deleteStoreId(),
			masks:   []string{"Name", "Description"},
			wantErr: errors.InvalidParameter,
		},
		{
			name: "no-version",
			orig: &UsernamePasswordDomainCredential{
				UsernamePasswordDomainCredential: &store.UsernamePasswordDomainCredential{
					Username: "user",
					Password: []byte("pass"),
					Domain:   "domain.com",
				},
			},
			chgFn:   deleteVersion(),
			masks:   []string{"Name", "Description"},
			wantErr: errors.InvalidParameter,
		},
		{
			name: "updating-non-existent-credential",
			orig: &UsernamePasswordDomainCredential{
				UsernamePasswordDomainCredential: &store.UsernamePasswordDomainCredential{
					Name:     "test-name-repo",
					Username: "user",
					Password: []byte("pass"),
					Domain:   "domain.com",
				},
			},
			chgFn:   combine(setPublicId("abcd_OOOOOOOOOO"), changeName("test-update-name-repo")),
			masks:   []string{"Name"},
			wantErr: errors.RecordNotFound,
		},
		{
			name: "empty-field-mask",
			orig: &UsernamePasswordDomainCredential{
				UsernamePasswordDomainCredential: &store.UsernamePasswordDomainCredential{
					Name:     "test-name-repo",
					Username: "user",
					Password: []byte("pass"),
					Domain:   "domain.com",
				},
			},
			chgFn:   changeName("test-update-name-repo"),
			wantErr: errors.EmptyFieldMask,
		},
		{
			name: "read-only-fields-in-field-mask",
			orig: &UsernamePasswordDomainCredential{
				UsernamePasswordDomainCredential: &store.UsernamePasswordDomainCredential{
					Name:     "test-name-repo",
					Username: "user",
					Password: []byte("pass"),
					Domain:   "domain.com",
				},
			},
			chgFn:   changeName("test-update-name-repo"),
			masks:   []string{"PublicId", "CreateTime", "UpdateTime", "ProjectId"},
			wantErr: errors.InvalidFieldMask,
		},
		{
			name: "unknown-field-in-field-mask",
			orig: &UsernamePasswordDomainCredential{
				UsernamePasswordDomainCredential: &store.UsernamePasswordDomainCredential{
					Name:     "test-name-repo",
					Username: "user",
					Password: []byte("pass"),
					Domain:   "domain.com",
				},
			},
			chgFn:   changeName("test-update-name-repo"),
			masks:   []string{"Bilbo"},
			wantErr: errors.InvalidFieldMask,
		},
		{
			name: "change-name",
			orig: &UsernamePasswordDomainCredential{
				UsernamePasswordDomainCredential: &store.UsernamePasswordDomainCredential{
					Name:     "test-name-repo",
					Username: "user",
					Password: []byte("pass"),
					Domain:   "domain.com",
				},
			},
			chgFn: changeName("test-update-name-repo"),
			masks: []string{"Name"},
			want: &UsernamePasswordDomainCredential{
				UsernamePasswordDomainCredential: &store.UsernamePasswordDomainCredential{
					Name:     "test-update-name-repo",
					Username: "user",
					Password: []byte("pass"),
					Domain:   "domain.com",
				},
			},
			wantCount: 1,
		},
		{
			name: "change-description",
			orig: &UsernamePasswordDomainCredential{
				UsernamePasswordDomainCredential: &store.UsernamePasswordDomainCredential{
					Description: "test-description-repo",
					Username:    "user",
					Password:    []byte("pass"),
					Domain:      "domain.com",
				},
			},
			chgFn: changeDescription("test-update-description-repo"),
			masks: []string{"Description"},
			want: &UsernamePasswordDomainCredential{
				UsernamePasswordDomainCredential: &store.UsernamePasswordDomainCredential{
					Description: "test-update-description-repo",
					Username:    "user",
					Password:    []byte("pass"),
					Domain:      "domain.com",
				},
			},
			wantCount: 1,
		},
		{
			name: "change-name-and-description",
			orig: &UsernamePasswordDomainCredential{
				UsernamePasswordDomainCredential: &store.UsernamePasswordDomainCredential{
					Name:        "test-name-repo",
					Description: "test-description-repo",
					Username:    "user",
					Password:    []byte("pass"),
					Domain:      "domain.com",
				},
			},
			chgFn: combine(changeDescription("test-update-description-repo"), changeName("test-update-name-repo")),
			masks: []string{"Name", "Description"},
			want: &UsernamePasswordDomainCredential{
				UsernamePasswordDomainCredential: &store.UsernamePasswordDomainCredential{
					Name:        "test-update-name-repo",
					Description: "test-update-description-repo",
					Username:    "user",
					Password:    []byte("pass"),
					Domain:      "domain.com",
				},
			},
			wantCount: 1,
		},
		{
			name: "change-username",
			orig: &UsernamePasswordDomainCredential{
				UsernamePasswordDomainCredential: &store.UsernamePasswordDomainCredential{
					Username: "user",
					Password: []byte("pass"),
					Domain:   "domain.com",
				},
			},
			chgFn: changeUser("test-update-user"),
			masks: []string{"Username"},
			want: &UsernamePasswordDomainCredential{
				UsernamePasswordDomainCredential: &store.UsernamePasswordDomainCredential{
					Username: "test-update-user",
					Password: []byte("pass"),
					Domain:   "domain.com",
				},
			},
			wantCount: 1,
		},
		{
			name: "change-password",
			orig: &UsernamePasswordDomainCredential{
				UsernamePasswordDomainCredential: &store.UsernamePasswordDomainCredential{
					Username: "user",
					Password: []byte("pass"),
					Domain:   "domain.com",
				},
			},
			chgFn: changePassword("test-update-pass"),
			masks: []string{"Password"},
			want: &UsernamePasswordDomainCredential{
				UsernamePasswordDomainCredential: &store.UsernamePasswordDomainCredential{
					Username: "user",
					Password: []byte("test-update-pass"),
					Domain:   "domain.com",
				},
			},
			wantCount: 1,
		},
		{
			name: "change-domain",
			orig: &UsernamePasswordDomainCredential{
				UsernamePasswordDomainCredential: &store.UsernamePasswordDomainCredential{
					Username: "user",
					Password: []byte("pass"),
					Domain:   "domain.com",
				},
			},
			chgFn: changeDomain("test-update-domain.com"),
			masks: []string{"Domain"},
			want: &UsernamePasswordDomainCredential{
				UsernamePasswordDomainCredential: &store.UsernamePasswordDomainCredential{
					Username: "user",
					Password: []byte("pass"),
					Domain:   "test-update-domain.com",
				},
			},
			wantCount: 1,
		},
		{
			name: "change-username-and-domain",
			orig: &UsernamePasswordDomainCredential{
				UsernamePasswordDomainCredential: &store.UsernamePasswordDomainCredential{
					Username: "user",
					Password: []byte("pass"),
					Domain:   "domain.com",
				},
			},
			chgFn: combine(changeUser("test-update-user"), changeDomain("test-update-domain.com")),
			masks: []string{"Username", "Domain"},
			want: &UsernamePasswordDomainCredential{
				UsernamePasswordDomainCredential: &store.UsernamePasswordDomainCredential{
					Username: "test-update-user",
					Password: []byte("pass"),
					Domain:   "test-update-domain.com",
				},
			},
			wantCount: 1,
		},
		{
			name: "change-username-and-password",
			orig: &UsernamePasswordDomainCredential{
				UsernamePasswordDomainCredential: &store.UsernamePasswordDomainCredential{
					Username: "user",
					Password: []byte("pass"),
					Domain:   "domain.com",
				},
			},
			chgFn: combine(changeUser("test-update-user"), changePassword("test-update-pass")),
			masks: []string{"Username", "Password"},
			want: &UsernamePasswordDomainCredential{
				UsernamePasswordDomainCredential: &store.UsernamePasswordDomainCredential{
					Username: "test-update-user",
					Password: []byte("test-update-pass"),
					Domain:   "domain.com",
				},
			},
			wantCount: 1,
		},
		{
			name: "change-username-and-password-and-domain",
			orig: &UsernamePasswordDomainCredential{
				UsernamePasswordDomainCredential: &store.UsernamePasswordDomainCredential{
					Username: "user",
					Password: []byte("pass"),
					Domain:   "domain.com",
				},
			},
			chgFn: combine(changeUser("test-update-user"), changePassword("test-update-pass"), changeDomain("test-update-domain.com")),
			masks: []string{"Username", "Password", "Domain"},
			want: &UsernamePasswordDomainCredential{
				UsernamePasswordDomainCredential: &store.UsernamePasswordDomainCredential{
					Username: "test-update-user",
					Password: []byte("test-update-pass"),
					Domain:   "test-update-domain.com",
				},
			},
			wantCount: 1,
		},
		{
			name: "do-not-delete-password",
			orig: &UsernamePasswordDomainCredential{
				UsernamePasswordDomainCredential: &store.UsernamePasswordDomainCredential{
					Username: "user",
					Password: []byte("pass"),
					Domain:   "domain.com",
				},
			},
			masks: []string{"Username"},
			chgFn: combine(changeUser("test-new-user"), changePassword("")),
			want: &UsernamePasswordDomainCredential{
				UsernamePasswordDomainCredential: &store.UsernamePasswordDomainCredential{
					Username: "test-new-user",
					Password: []byte("pass"),
					Domain:   "domain.com",
				},
			},
			wantCount: 1,
		},
		{
			name: "do-not-delete-username",
			orig: &UsernamePasswordDomainCredential{
				UsernamePasswordDomainCredential: &store.UsernamePasswordDomainCredential{
					Username: "user",
					Password: []byte("pass"),
					Domain:   "domain.com",
				},
			},
			masks: []string{"Password"},
			chgFn: combine(changeUser(""), changePassword("test-new-password")),
			want: &UsernamePasswordDomainCredential{
				UsernamePasswordDomainCredential: &store.UsernamePasswordDomainCredential{
					Username: "user",
					Password: []byte("test-new-password"),
					Domain:   "domain.com",
				},
			},
			wantCount: 1,
		},
		{
			name: "delete-name",
			orig: &UsernamePasswordDomainCredential{
				UsernamePasswordDomainCredential: &store.UsernamePasswordDomainCredential{
					Name:        "test-name-repo",
					Description: "test-description-repo",
					Username:    "user",
					Password:    []byte("pass"),
					Domain:      "domain.com",
				},
			},
			masks: []string{"Name"},
			chgFn: combine(changeDescription("test-update-description-repo"), changeName("")),
			want: &UsernamePasswordDomainCredential{
				UsernamePasswordDomainCredential: &store.UsernamePasswordDomainCredential{
					Description: "test-description-repo",
					Username:    "user",
					Password:    []byte("pass"),
					Domain:      "domain.com",
				},
			},
			wantCount: 1,
		},
		{
			name: "delete-description",
			orig: &UsernamePasswordDomainCredential{
				UsernamePasswordDomainCredential: &store.UsernamePasswordDomainCredential{
					Name:        "test-name-repo",
					Description: "test-description-repo",
					Username:    "user",
					Password:    []byte("pass"),
					Domain:      "domain.com",
				},
			},
			masks: []string{"Description"},
			chgFn: combine(changeDescription(""), changeName("test-update-name-repo")),
			want: &UsernamePasswordDomainCredential{
				UsernamePasswordDomainCredential: &store.UsernamePasswordDomainCredential{
					Name:     "test-name-repo",
					Username: "user",
					Password: []byte("pass"),
					Domain:   "domain.com",
				},
			},
			wantCount: 1,
		},
		{
			name: "do-not-delete-name",
			orig: &UsernamePasswordDomainCredential{
				UsernamePasswordDomainCredential: &store.UsernamePasswordDomainCredential{
					Name:        "test-name-repo",
					Description: "test-description-repo",
					Username:    "user",
					Password:    []byte("pass"),
					Domain:      "domain.com",
				},
			},
			masks: []string{"Description"},
			chgFn: combine(changeDescription("test-update-description-repo"), changeName("")),
			want: &UsernamePasswordDomainCredential{
				UsernamePasswordDomainCredential: &store.UsernamePasswordDomainCredential{
					Name:        "test-name-repo",
					Description: "test-update-description-repo",
					Username:    "user",
					Password:    []byte("pass"),
					Domain:      "domain.com",
				},
			},
			wantCount: 1,
		},
		{
			name: "do-not-delete-description",
			orig: &UsernamePasswordDomainCredential{
				UsernamePasswordDomainCredential: &store.UsernamePasswordDomainCredential{
					Name:        "test-name-repo",
					Description: "test-description-repo",
					Username:    "user",
					Password:    []byte("pass"),
					Domain:      "domain.com",
				},
			},
			masks: []string{"Name"},
			chgFn: combine(changeDescription(""), changeName("test-update-name-repo")),
			want: &UsernamePasswordDomainCredential{
				UsernamePasswordDomainCredential: &store.UsernamePasswordDomainCredential{
					Name:        "test-update-name-repo",
					Description: "test-description-repo",
					Username:    "user",
					Password:    []byte("pass"),
					Domain:      "domain.com",
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
			kkms := kms.TestKms(t, conn, wrapper)
			repo, err := NewRepository(ctx, rw, rw, kkms)
			assert.NoError(err)
			require.NotNil(repo)

			_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
			store := TestCredentialStore(t, conn, wrapper, prj.GetPublicId())
			tt.orig.StoreId = store.PublicId

			orig, err := repo.CreateUsernamePasswordDomainCredential(ctx, prj.GetPublicId(), tt.orig)
			assert.NoError(err)
			require.NotNil(orig)

			if tt.chgFn != nil {
				orig = tt.chgFn(orig)
			}
			var version uint32
			if orig != nil {
				version = orig.GetVersion()
			}
			got, gotCount, err := repo.UpdateUsernamePasswordDomainCredential(ctx, prj.GetPublicId(), orig, version, tt.masks)
			if tt.wantErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantErr), err), "want err: %q got: %q", tt.wantErr, err)
				assert.Equal(tt.wantCount, gotCount, "row count")
				assert.Nil(got)
				return
			}
			assert.NoError(err)
			assert.Empty(tt.orig.PublicId)
			require.NotNil(got)
			assertPublicId(t, globals.UsernamePasswordDomainCredentialPrefix, got.PublicId)
			assert.Equal(tt.wantCount, gotCount, "row count")
			assert.NotSame(tt.orig, got)
			assert.Equal(tt.orig.StoreId, got.StoreId)
			underlyingDB, err := conn.SqlDB(ctx)
			require.NoError(err)
			dbassert := dbassert.New(t, underlyingDB)
			if tt.want.Name == "" {
				got := got.clone()
				dbassert.IsNull(got, "name")
			} else {
				assert.Equal(tt.want.Name, got.Name)
			}

			if tt.want.Description == "" {
				got := got.clone()
				dbassert.IsNull(got, "description")
			} else {
				assert.Equal(tt.want.Description, got.Description)
			}

			assert.Equal(tt.want.Username, got.Username)

			// Validate only passwordHmac is returned
			assert.Empty(got.Password)
			assert.Empty(got.CtPassword)
			assert.NotEmpty(got.PasswordHmac)

			// Validate hmac
			databaseWrapper, err := kkms.GetWrapper(context.Background(), prj.GetPublicId(), kms.KeyPurposeDatabase)
			require.NoError(err)
			hm, err := crypto.HmacSha256(ctx, tt.want.Password, databaseWrapper, []byte(store.GetPublicId()), nil, crypto.WithEd25519())
			require.NoError(err)
			assert.Equal([]byte(hm), got.PasswordHmac)

			if tt.wantCount > 0 {
				assert.NoError(db.TestVerifyOplog(t, rw, got.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second)))
			}
		})
	}
}

func TestRepository_UpdatePasswordCredential(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)

	changeName := func(n string) func(credential *PasswordCredential) *PasswordCredential {
		return func(c *PasswordCredential) *PasswordCredential {
			c.Name = n
			return c
		}
	}

	changeDescription := func(d string) func(*PasswordCredential) *PasswordCredential {
		return func(c *PasswordCredential) *PasswordCredential {
			c.Description = d
			return c
		}
	}

	makeNil := func() func(*PasswordCredential) *PasswordCredential {
		return func(_ *PasswordCredential) *PasswordCredential {
			return nil
		}
	}

	makeEmbeddedNil := func() func(*PasswordCredential) *PasswordCredential {
		return func(_ *PasswordCredential) *PasswordCredential {
			return &PasswordCredential{}
		}
	}

	setPublicId := func(n string) func(*PasswordCredential) *PasswordCredential {
		return func(c *PasswordCredential) *PasswordCredential {
			c.PublicId = n
			return c
		}
	}

	deleteStoreId := func() func(*PasswordCredential) *PasswordCredential {
		return func(c *PasswordCredential) *PasswordCredential {
			c.StoreId = ""
			return c
		}
	}

	deleteVersion := func() func(*PasswordCredential) *PasswordCredential {
		return func(c *PasswordCredential) *PasswordCredential {
			c.Version = 0
			return c
		}
	}

	changePassword := func(d string) func(*PasswordCredential) *PasswordCredential {
		return func(c *PasswordCredential) *PasswordCredential {
			c.Password = []byte(d)
			return c
		}
	}

	combine := func(fns ...func(cs *PasswordCredential) *PasswordCredential) func(*PasswordCredential) *PasswordCredential {
		return func(c *PasswordCredential) *PasswordCredential {
			for _, fn := range fns {
				c = fn(c)
			}
			return c
		}
	}

	tests := []struct {
		name      string
		orig      *PasswordCredential
		chgFn     func(*PasswordCredential) *PasswordCredential
		masks     []string
		want      *PasswordCredential
		wantCount int
		wantErr   errors.Code
	}{
		{
			name: "nil-credential",
			orig: &PasswordCredential{
				PasswordCredential: &store.PasswordCredential{
					Password: []byte("pass"),
				},
			},
			chgFn:   makeNil(),
			masks:   []string{"Name", "Description"},
			wantErr: errors.InvalidParameter,
		},
		{
			name: "nil-embedded-credential",
			orig: &PasswordCredential{
				PasswordCredential: &store.PasswordCredential{
					Password: []byte("pass"),
				},
			},
			chgFn:   makeEmbeddedNil(),
			masks:   []string{"Name", "Description"},
			wantErr: errors.InvalidParameter,
		},
		{
			name: "no-public-id",
			orig: &PasswordCredential{
				PasswordCredential: &store.PasswordCredential{
					Password: []byte("pass"),
				},
			},
			chgFn:   setPublicId(""),
			masks:   []string{"Name", "Description"},
			wantErr: errors.InvalidPublicId,
		},
		{
			name: "no-store-id",
			orig: &PasswordCredential{
				PasswordCredential: &store.PasswordCredential{
					Password: []byte("pass"),
				},
			},
			chgFn:   deleteStoreId(),
			masks:   []string{"Name", "Description"},
			wantErr: errors.InvalidParameter,
		},
		{
			name: "no-version",
			orig: &PasswordCredential{
				PasswordCredential: &store.PasswordCredential{
					Password: []byte("pass"),
				},
			},
			chgFn:   deleteVersion(),
			masks:   []string{"Name", "Description"},
			wantErr: errors.InvalidParameter,
		},
		{
			name: "updating-non-existent-credential",
			orig: &PasswordCredential{
				PasswordCredential: &store.PasswordCredential{
					Name:     "test-name-repo",
					Password: []byte("pass"),
				},
			},
			chgFn:   combine(setPublicId("abcd_OOOOOOOOOO"), changeName("test-update-name-repo")),
			masks:   []string{"Name"},
			wantErr: errors.RecordNotFound,
		},
		{
			name: "empty-field-mask",
			orig: &PasswordCredential{
				PasswordCredential: &store.PasswordCredential{
					Name:     "test-name-repo",
					Password: []byte("pass"),
				},
			},
			chgFn:   changeName("test-update-name-repo"),
			wantErr: errors.EmptyFieldMask,
		},
		{
			name: "read-only-fields-in-field-mask",
			orig: &PasswordCredential{
				PasswordCredential: &store.PasswordCredential{
					Name:     "test-name-repo",
					Password: []byte("pass"),
				},
			},
			chgFn:   changeName("test-update-name-repo"),
			masks:   []string{"PublicId", "CreateTime", "UpdateTime", "ProjectId"},
			wantErr: errors.InvalidFieldMask,
		},
		{
			name: "unknown-field-in-field-mask",
			orig: &PasswordCredential{
				PasswordCredential: &store.PasswordCredential{
					Name:     "test-name-repo",
					Password: []byte("pass"),
				},
			},
			chgFn:   changeName("test-update-name-repo"),
			masks:   []string{"Bilbo"},
			wantErr: errors.InvalidFieldMask,
		},
		{
			name: "change-name",
			orig: &PasswordCredential{
				PasswordCredential: &store.PasswordCredential{
					Name:     "test-name-repo",
					Password: []byte("pass"),
				},
			},
			chgFn: changeName("test-update-name-repo"),
			masks: []string{"Name"},
			want: &PasswordCredential{
				PasswordCredential: &store.PasswordCredential{
					Name:     "test-update-name-repo",
					Password: []byte("pass"),
				},
			},
			wantCount: 1,
		},
		{
			name: "change-description",
			orig: &PasswordCredential{
				PasswordCredential: &store.PasswordCredential{
					Description: "test-description-repo",
					Password:    []byte("pass"),
				},
			},
			chgFn: changeDescription("test-update-description-repo"),
			masks: []string{"Description"},
			want: &PasswordCredential{
				PasswordCredential: &store.PasswordCredential{
					Description: "test-update-description-repo",
					Password:    []byte("pass"),
				},
			},
			wantCount: 1,
		},
		{
			name: "change-name-and-description",
			orig: &PasswordCredential{
				PasswordCredential: &store.PasswordCredential{
					Name:        "test-name-repo",
					Description: "test-description-repo",
					Password:    []byte("pass"),
				},
			},
			chgFn: combine(changeDescription("test-update-description-repo"), changeName("test-update-name-repo")),
			masks: []string{"Name", "Description"},
			want: &PasswordCredential{
				PasswordCredential: &store.PasswordCredential{
					Name:        "test-update-name-repo",
					Description: "test-update-description-repo",
					Password:    []byte("pass"),
				},
			},
			wantCount: 1,
		},
		{
			name: "change-password",
			orig: &PasswordCredential{
				PasswordCredential: &store.PasswordCredential{
					Password: []byte("pass"),
				},
			},
			chgFn: changePassword("test-update-pass"),
			masks: []string{"Password"},
			want: &PasswordCredential{
				PasswordCredential: &store.PasswordCredential{
					Password: []byte("test-update-pass"),
				},
			},
			wantCount: 1,
		},
		{
			name: "do-not-delete-password",
			orig: &PasswordCredential{
				PasswordCredential: &store.PasswordCredential{
					Password: []byte("pass"),
				},
			},
			masks: []string{"Name"},
			chgFn: combine(changeName("new-name"), changePassword("")),
			want: &PasswordCredential{
				PasswordCredential: &store.PasswordCredential{
					Name:     "new-name",
					Password: []byte("pass"),
				},
			},
			wantCount: 1,
		},
		{
			name: "delete-name",
			orig: &PasswordCredential{
				PasswordCredential: &store.PasswordCredential{
					Name:        "test-name-repo",
					Description: "test-description-repo",
					Password:    []byte("pass"),
				},
			},
			masks: []string{"Name"},
			chgFn: combine(changeDescription("test-update-description-repo"), changeName("")),
			want: &PasswordCredential{
				PasswordCredential: &store.PasswordCredential{
					Description: "test-description-repo",
					Password:    []byte("pass"),
				},
			},
			wantCount: 1,
		},
		{
			name: "delete-description",
			orig: &PasswordCredential{
				PasswordCredential: &store.PasswordCredential{
					Name:        "test-name-repo",
					Description: "test-description-repo",
					Password:    []byte("pass"),
				},
			},
			masks: []string{"Description"},
			chgFn: combine(changeDescription(""), changeName("test-update-name-repo")),
			want: &PasswordCredential{
				PasswordCredential: &store.PasswordCredential{
					Name:     "test-name-repo",
					Password: []byte("pass"),
				},
			},
			wantCount: 1,
		},
		{
			name: "do-not-delete-name",
			orig: &PasswordCredential{
				PasswordCredential: &store.PasswordCredential{
					Name:        "test-name-repo",
					Description: "test-description-repo",
					Password:    []byte("pass"),
				},
			},
			masks: []string{"Description"},
			chgFn: combine(changeDescription("test-update-description-repo"), changeName("")),
			want: &PasswordCredential{
				PasswordCredential: &store.PasswordCredential{
					Name:        "test-name-repo",
					Description: "test-update-description-repo",
					Password:    []byte("pass"),
				},
			},
			wantCount: 1,
		},
		{
			name: "do-not-delete-description",
			orig: &PasswordCredential{
				PasswordCredential: &store.PasswordCredential{
					Name:        "test-name-repo",
					Description: "test-description-repo",
					Password:    []byte("pass"),
				},
			},
			masks: []string{"Name"},
			chgFn: combine(changeDescription(""), changeName("test-update-name-repo")),
			want: &PasswordCredential{
				PasswordCredential: &store.PasswordCredential{
					Name:        "test-update-name-repo",
					Description: "test-description-repo",
					Password:    []byte("pass"),
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
			kkms := kms.TestKms(t, conn, wrapper)
			repo, err := NewRepository(ctx, rw, rw, kkms)
			assert.NoError(err)
			require.NotNil(repo)

			_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
			store := TestCredentialStore(t, conn, wrapper, prj.GetPublicId())
			tt.orig.StoreId = store.PublicId

			orig, err := repo.CreatePasswordCredential(ctx, prj.GetPublicId(), tt.orig)
			assert.NoError(err)
			require.NotNil(orig)

			if tt.chgFn != nil {
				orig = tt.chgFn(orig)
			}
			var version uint32
			if orig != nil {
				version = orig.GetVersion()
			}
			got, gotCount, err := repo.UpdatePasswordCredential(ctx, prj.GetPublicId(), orig, version, tt.masks)
			if tt.wantErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantErr), err), "want err: %q got: %q", tt.wantErr, err)
				assert.Equal(tt.wantCount, gotCount, "row count")
				assert.Nil(got)
				return
			}
			assert.NoError(err)
			assert.Empty(tt.orig.PublicId)
			require.NotNil(got)
			assertPublicId(t, globals.PasswordCredentialPrefix, got.PublicId)
			assert.Equal(tt.wantCount, gotCount, "row count")
			assert.NotSame(tt.orig, got)
			assert.Equal(tt.orig.StoreId, got.StoreId)
			underlyingDB, err := conn.SqlDB(ctx)
			require.NoError(err)
			dbassert := dbassert.New(t, underlyingDB)
			if tt.want.Name == "" {
				got := got.clone()
				dbassert.IsNull(got, "name")
			} else {
				assert.Equal(tt.want.Name, got.Name)
			}

			if tt.want.Description == "" {
				got := got.clone()
				dbassert.IsNull(got, "description")
			} else {
				assert.Equal(tt.want.Description, got.Description)
			}

			assert.Equal(tt.want.Name, got.Name)

			// Validate only passwordHmac is returned
			assert.Empty(got.Password)
			assert.Empty(got.CtPassword)
			assert.NotEmpty(got.PasswordHmac)

			// Validate hmac
			databaseWrapper, err := kkms.GetWrapper(context.Background(), prj.GetPublicId(), kms.KeyPurposeDatabase)
			require.NoError(err)
			hm, err := crypto.HmacSha256(ctx, tt.want.Password, databaseWrapper, []byte(store.GetPublicId()), nil, crypto.WithEd25519())
			require.NoError(err)
			assert.Equal([]byte(hm), got.PasswordHmac)

			if tt.wantCount > 0 {
				assert.NoError(db.TestVerifyOplog(t, rw, got.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second)))
			}
		})
	}
}

func TestRepository_UpdatePasswordCredentialKeyUpdate(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	assert, require := assert.New(t), require.New(t)
	ctx := context.Background()
	kkms := kms.TestKms(t, conn, wrapper)
	repo, err := NewRepository(ctx, rw, rw, kkms)
	require.NoError(err)

	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	credStore := TestCredentialStore(t, conn, wrapper, prj.GetPublicId())
	orig, err := repo.CreateUsernamePasswordCredential(ctx, prj.GetPublicId(), &UsernamePasswordCredential{
		UsernamePasswordCredential: &store.UsernamePasswordCredential{
			Username: "user",
			Password: []byte("pass"),
			StoreId:  credStore.PublicId,
		},
	})
	require.NoError(err)

	err = kkms.RotateKeys(ctx, prj.GetPublicId())
	require.NoError(err)

	orig.Password = []byte("pass1") // Company policy to change password every 3 months

	got, _, err := repo.UpdateUsernamePasswordCredential(ctx, prj.GetPublicId(), orig, orig.GetVersion(), []string{"Password"})
	require.NoError(err)

	// Validate that the KeyId has changed
	assert.NotEqual(orig.KeyId, got.KeyId)

	// Validate hmac
	databaseWrapper, err := kkms.GetWrapper(context.Background(), prj.GetPublicId(), kms.KeyPurposeDatabase, kms.WithKeyId(got.KeyId))
	require.NoError(err)
	hm, err := crypto.HmacSha256(ctx, orig.Password, databaseWrapper, []byte(credStore.GetPublicId()), nil, crypto.WithEd25519())
	require.NoError(err)
	assert.Equal([]byte(hm), got.PasswordHmac)
}

func TestRepository_UpdateSshPrivateKeyCredential(t *testing.T) {
	const testSecondarySshPrivateKeyPem = `
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDxfwhEAZKrnsbQxOjVA3PFiB3bW3tSpNKx8TdMiCqlzQAAAJDmpbfr5qW3
6wAAAAtzc2gtZWQyNTUxOQAAACDxfwhEAZKrnsbQxOjVA3PFiB3bW3tSpNKx8TdMiCqlzQ
AAAEBvvkQkH06ad2GpX1VVARzu9NkHA6gzamAaQ/hkn5FuZvF/CEQBkquextDE6NUDc8WI
Hdtbe1Kk0rHxN0yIKqXNAAAACWplZmZAYXJjaAECAwQ=
-----END OPENSSH PRIVATE KEY-----
`

	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)

	changeName := func(n string) func(credential *SshPrivateKeyCredential) *SshPrivateKeyCredential {
		return func(c *SshPrivateKeyCredential) *SshPrivateKeyCredential {
			c.Name = n
			return c
		}
	}

	changeDescription := func(d string) func(*SshPrivateKeyCredential) *SshPrivateKeyCredential {
		return func(c *SshPrivateKeyCredential) *SshPrivateKeyCredential {
			c.Description = d
			return c
		}
	}

	makeNil := func() func(*SshPrivateKeyCredential) *SshPrivateKeyCredential {
		return func(_ *SshPrivateKeyCredential) *SshPrivateKeyCredential {
			return nil
		}
	}

	makeEmbeddedNil := func() func(*SshPrivateKeyCredential) *SshPrivateKeyCredential {
		return func(_ *SshPrivateKeyCredential) *SshPrivateKeyCredential {
			return &SshPrivateKeyCredential{}
		}
	}

	setPublicId := func(n string) func(*SshPrivateKeyCredential) *SshPrivateKeyCredential {
		return func(c *SshPrivateKeyCredential) *SshPrivateKeyCredential {
			c.PublicId = n
			return c
		}
	}

	deleteStoreId := func() func(*SshPrivateKeyCredential) *SshPrivateKeyCredential {
		return func(c *SshPrivateKeyCredential) *SshPrivateKeyCredential {
			c.StoreId = ""
			return c
		}
	}

	deleteVersion := func() func(*SshPrivateKeyCredential) *SshPrivateKeyCredential {
		return func(c *SshPrivateKeyCredential) *SshPrivateKeyCredential {
			c.Version = 0
			return c
		}
	}

	changeUser := func(n string) func(credential *SshPrivateKeyCredential) *SshPrivateKeyCredential {
		return func(c *SshPrivateKeyCredential) *SshPrivateKeyCredential {
			c.Username = n
			return c
		}
	}

	changePrivateKey := func(d string) func(*SshPrivateKeyCredential) *SshPrivateKeyCredential {
		return func(c *SshPrivateKeyCredential) *SshPrivateKeyCredential {
			c.PrivateKey = []byte(d)
			return c
		}
	}

	changePrivateKeyPassphrase := func(d string) func(*SshPrivateKeyCredential) *SshPrivateKeyCredential {
		return func(c *SshPrivateKeyCredential) *SshPrivateKeyCredential {
			c.PrivateKeyPassphrase = []byte(d)
			return c
		}
	}

	combine := func(fns ...func(cs *SshPrivateKeyCredential) *SshPrivateKeyCredential) func(*SshPrivateKeyCredential) *SshPrivateKeyCredential {
		return func(c *SshPrivateKeyCredential) *SshPrivateKeyCredential {
			for _, fn := range fns {
				c = fn(c)
			}
			return c
		}
	}

	tests := []struct {
		name      string
		orig      *SshPrivateKeyCredential
		chgFn     func(*SshPrivateKeyCredential) *SshPrivateKeyCredential
		masks     []string
		want      *SshPrivateKeyCredential
		wantCount int
		wantErr   errors.Code
	}{
		{
			name: "nil-credential",
			orig: &SshPrivateKeyCredential{
				SshPrivateKeyCredential: &store.SshPrivateKeyCredential{
					Username:   "user",
					PrivateKey: []byte(TestSshPrivateKeyPem),
				},
			},
			chgFn:   makeNil(),
			masks:   []string{"Name", "Description"},
			wantErr: errors.InvalidParameter,
		},
		{
			name: "nil-embedded-credential",
			orig: &SshPrivateKeyCredential{
				SshPrivateKeyCredential: &store.SshPrivateKeyCredential{
					Username:   "user",
					PrivateKey: []byte(TestSshPrivateKeyPem),
				},
			},
			chgFn:   makeEmbeddedNil(),
			masks:   []string{"Name", "Description"},
			wantErr: errors.InvalidParameter,
		},
		{
			name: "no-public-id",
			orig: &SshPrivateKeyCredential{
				SshPrivateKeyCredential: &store.SshPrivateKeyCredential{
					Username:   "user",
					PrivateKey: []byte(TestSshPrivateKeyPem),
				},
			},
			chgFn:   setPublicId(""),
			masks:   []string{"Name", "Description"},
			wantErr: errors.InvalidPublicId,
		},
		{
			name: "no-store-id",
			orig: &SshPrivateKeyCredential{
				SshPrivateKeyCredential: &store.SshPrivateKeyCredential{
					Username:   "user",
					PrivateKey: []byte(TestSshPrivateKeyPem),
				},
			},
			chgFn:   deleteStoreId(),
			masks:   []string{"Name", "Description"},
			wantErr: errors.InvalidParameter,
		},
		{
			name: "no-version",
			orig: &SshPrivateKeyCredential{
				SshPrivateKeyCredential: &store.SshPrivateKeyCredential{
					Username:   "user",
					PrivateKey: []byte(TestSshPrivateKeyPem),
				},
			},
			chgFn:   deleteVersion(),
			masks:   []string{"Name", "Description"},
			wantErr: errors.InvalidParameter,
		},
		{
			name: "updating-non-existent-credential",
			orig: &SshPrivateKeyCredential{
				SshPrivateKeyCredential: &store.SshPrivateKeyCredential{
					Name:       "test-name-repo",
					Username:   "user",
					PrivateKey: []byte(TestSshPrivateKeyPem),
				},
			},
			chgFn:   combine(setPublicId("abcd_OOOOOOOOOO"), changeName("test-update-name-repo")),
			masks:   []string{"Name"},
			wantErr: errors.RecordNotFound,
		},
		{
			name: "empty-field-mask",
			orig: &SshPrivateKeyCredential{
				SshPrivateKeyCredential: &store.SshPrivateKeyCredential{
					Name:       "test-name-repo",
					Username:   "user",
					PrivateKey: []byte(TestSshPrivateKeyPem),
				},
			},
			chgFn:   changeName("test-update-name-repo"),
			wantErr: errors.EmptyFieldMask,
		},
		{
			name: "read-only-fields-in-field-mask",
			orig: &SshPrivateKeyCredential{
				SshPrivateKeyCredential: &store.SshPrivateKeyCredential{
					Name:       "test-name-repo",
					Username:   "user",
					PrivateKey: []byte(TestSshPrivateKeyPem),
				},
			},
			chgFn:   changeName("test-update-name-repo"),
			masks:   []string{"PublicId", "CreateTime", "UpdateTime", "ProjectId"},
			wantErr: errors.InvalidFieldMask,
		},
		{
			name: "unknown-field-in-field-mask",
			orig: &SshPrivateKeyCredential{
				SshPrivateKeyCredential: &store.SshPrivateKeyCredential{
					Name:       "test-name-repo",
					Username:   "user",
					PrivateKey: []byte(TestSshPrivateKeyPem),
				},
			},
			chgFn:   changeName("test-update-name-repo"),
			masks:   []string{"Bilbo"},
			wantErr: errors.InvalidFieldMask,
		},
		{
			name: "change-name",
			orig: &SshPrivateKeyCredential{
				SshPrivateKeyCredential: &store.SshPrivateKeyCredential{
					Name:       "test-name-repo",
					Username:   "user",
					PrivateKey: []byte(TestSshPrivateKeyPem),
				},
			},
			chgFn: changeName("test-update-name-repo"),
			masks: []string{"Name"},
			want: &SshPrivateKeyCredential{
				SshPrivateKeyCredential: &store.SshPrivateKeyCredential{
					Name:       "test-update-name-repo",
					Username:   "user",
					PrivateKey: []byte(TestSshPrivateKeyPem),
				},
			},
			wantCount: 1,
		},
		{
			name: "change-description",
			orig: &SshPrivateKeyCredential{
				SshPrivateKeyCredential: &store.SshPrivateKeyCredential{
					Description: "test-description-repo",
					Username:    "user",
					PrivateKey:  []byte(TestSshPrivateKeyPem),
				},
			},
			chgFn: changeDescription("test-update-description-repo"),
			masks: []string{"Description"},
			want: &SshPrivateKeyCredential{
				SshPrivateKeyCredential: &store.SshPrivateKeyCredential{
					Description: "test-update-description-repo",
					Username:    "user",
					PrivateKey:  []byte(TestSshPrivateKeyPem),
				},
			},
			wantCount: 1,
		},
		{
			name: "change-name-and-description",
			orig: &SshPrivateKeyCredential{
				SshPrivateKeyCredential: &store.SshPrivateKeyCredential{
					Name:        "test-name-repo",
					Description: "test-description-repo",
					Username:    "user",
					PrivateKey:  []byte(TestSshPrivateKeyPem),
				},
			},
			chgFn: combine(changeDescription("test-update-description-repo"), changeName("test-update-name-repo")),
			masks: []string{"Name", "Description"},
			want: &SshPrivateKeyCredential{
				SshPrivateKeyCredential: &store.SshPrivateKeyCredential{
					Name:        "test-update-name-repo",
					Description: "test-update-description-repo",
					Username:    "user",
					PrivateKey:  []byte(TestSshPrivateKeyPem),
				},
			},
			wantCount: 1,
		},
		{
			name: "change-username",
			orig: &SshPrivateKeyCredential{
				SshPrivateKeyCredential: &store.SshPrivateKeyCredential{
					Username:   "user",
					PrivateKey: []byte(TestSshPrivateKeyPem),
				},
			},
			chgFn: changeUser("test-update-user"),
			masks: []string{"Username"},
			want: &SshPrivateKeyCredential{
				SshPrivateKeyCredential: &store.SshPrivateKeyCredential{
					Username:   "test-update-user",
					PrivateKey: []byte(TestSshPrivateKeyPem),
				},
			},
			wantCount: 1,
		},
		{
			name: "change-private-key",
			orig: &SshPrivateKeyCredential{
				SshPrivateKeyCredential: &store.SshPrivateKeyCredential{
					Username:   "user",
					PrivateKey: []byte(TestSshPrivateKeyPem),
				},
			},
			chgFn: changePrivateKey(testSecondarySshPrivateKeyPem),
			masks: []string{"PrivateKey"},
			want: &SshPrivateKeyCredential{
				SshPrivateKeyCredential: &store.SshPrivateKeyCredential{
					Username:   "user",
					PrivateKey: []byte(testSecondarySshPrivateKeyPem),
				},
			},
			wantCount: 1,
		},
		{
			name: "change-private-key-and-passphrase",
			orig: &SshPrivateKeyCredential{
				SshPrivateKeyCredential: &store.SshPrivateKeyCredential{
					Username:             "user",
					PrivateKey:           []byte(TestSshPrivateKeyPem),
					PrivateKeyPassphrase: []byte("foobar"),
				},
			},
			chgFn: combine(changePrivateKey(testSecondarySshPrivateKeyPem), changePrivateKeyPassphrase("barfoo")),
			masks: []string{"PrivateKeyPassphrase"},
			want: &SshPrivateKeyCredential{
				SshPrivateKeyCredential: &store.SshPrivateKeyCredential{
					Username:             "user",
					PrivateKey:           []byte(testSecondarySshPrivateKeyPem),
					PrivateKeyPassphrase: []byte("barfoo"),
				},
			},
			wantCount: 1,
		},
		{
			name: "change-username-and-private-key",
			orig: &SshPrivateKeyCredential{
				SshPrivateKeyCredential: &store.SshPrivateKeyCredential{
					Username:   "user",
					PrivateKey: []byte(TestSshPrivateKeyPem),
				},
			},
			chgFn: combine(changeUser("test-update-user"), changePrivateKey(testSecondarySshPrivateKeyPem)),
			masks: []string{"Username", "PrivateKey"},
			want: &SshPrivateKeyCredential{
				SshPrivateKeyCredential: &store.SshPrivateKeyCredential{
					Username:   "test-update-user",
					PrivateKey: []byte(testSecondarySshPrivateKeyPem),
				},
			},
			wantCount: 1,
		},
		{
			name: "do-not-delete-private-key",
			orig: &SshPrivateKeyCredential{
				SshPrivateKeyCredential: &store.SshPrivateKeyCredential{
					Username:   "user",
					PrivateKey: []byte(TestSshPrivateKeyPem),
				},
			},
			masks: []string{"Username"},
			chgFn: combine(changeUser("test-new-user"), changePrivateKey("")),
			want: &SshPrivateKeyCredential{
				SshPrivateKeyCredential: &store.SshPrivateKeyCredential{
					Username:   "test-new-user",
					PrivateKey: []byte(TestSshPrivateKeyPem),
				},
			},
			wantCount: 1,
		},
		{
			name: "do-not-delete-username",
			orig: &SshPrivateKeyCredential{
				SshPrivateKeyCredential: &store.SshPrivateKeyCredential{
					Username:   "user",
					PrivateKey: []byte(TestSshPrivateKeyPem),
				},
			},
			masks: []string{"PrivateKey"},
			chgFn: combine(changeUser(""), changePrivateKey(testSecondarySshPrivateKeyPem)),
			want: &SshPrivateKeyCredential{
				SshPrivateKeyCredential: &store.SshPrivateKeyCredential{
					Username:   "user",
					PrivateKey: []byte(testSecondarySshPrivateKeyPem),
				},
			},
			wantCount: 1,
		},
		{
			name: "delete-name",
			orig: &SshPrivateKeyCredential{
				SshPrivateKeyCredential: &store.SshPrivateKeyCredential{
					Name:        "test-name-repo",
					Description: "test-description-repo",
					Username:    "user",
					PrivateKey:  []byte(TestSshPrivateKeyPem),
				},
			},
			masks: []string{"Name"},
			chgFn: combine(changeDescription("test-update-description-repo"), changeName("")),
			want: &SshPrivateKeyCredential{
				SshPrivateKeyCredential: &store.SshPrivateKeyCredential{
					Description: "test-description-repo",
					Username:    "user",
					PrivateKey:  []byte(TestSshPrivateKeyPem),
				},
			},
			wantCount: 1,
		},
		{
			name: "delete-description",
			orig: &SshPrivateKeyCredential{
				SshPrivateKeyCredential: &store.SshPrivateKeyCredential{
					Name:        "test-name-repo",
					Description: "test-description-repo",
					Username:    "user",
					PrivateKey:  []byte(TestSshPrivateKeyPem),
				},
			},
			masks: []string{"Description"},
			chgFn: combine(changeDescription(""), changeName("test-update-name-repo")),
			want: &SshPrivateKeyCredential{
				SshPrivateKeyCredential: &store.SshPrivateKeyCredential{
					Name:       "test-name-repo",
					Username:   "user",
					PrivateKey: []byte(TestSshPrivateKeyPem),
				},
			},
			wantCount: 1,
		},
		{
			name: "do-not-delete-name",
			orig: &SshPrivateKeyCredential{
				SshPrivateKeyCredential: &store.SshPrivateKeyCredential{
					Name:        "test-name-repo",
					Description: "test-description-repo",
					Username:    "user",
					PrivateKey:  []byte(TestSshPrivateKeyPem),
				},
			},
			masks: []string{"Description"},
			chgFn: combine(changeDescription("test-update-description-repo"), changeName("")),
			want: &SshPrivateKeyCredential{
				SshPrivateKeyCredential: &store.SshPrivateKeyCredential{
					Name:        "test-name-repo",
					Description: "test-update-description-repo",
					Username:    "user",
					PrivateKey:  []byte(TestSshPrivateKeyPem),
				},
			},
			wantCount: 1,
		},
		{
			name: "do-not-delete-description",
			orig: &SshPrivateKeyCredential{
				SshPrivateKeyCredential: &store.SshPrivateKeyCredential{
					Name:        "test-name-repo",
					Description: "test-description-repo",
					Username:    "user",
					PrivateKey:  []byte(TestSshPrivateKeyPem),
				},
			},
			masks: []string{"Name"},
			chgFn: combine(changeDescription(""), changeName("test-update-name-repo")),
			want: &SshPrivateKeyCredential{
				SshPrivateKeyCredential: &store.SshPrivateKeyCredential{
					Name:        "test-update-name-repo",
					Description: "test-description-repo",
					Username:    "user",
					PrivateKey:  []byte(TestSshPrivateKeyPem),
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
			kkms := kms.TestKms(t, conn, wrapper)
			repo, err := NewRepository(ctx, rw, rw, kkms)
			assert.NoError(err)
			require.NotNil(repo)

			_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
			store := TestCredentialStore(t, conn, wrapper, prj.GetPublicId())
			tt.orig.StoreId = store.PublicId

			orig, err := repo.CreateSshPrivateKeyCredential(ctx, prj.GetPublicId(), tt.orig)
			assert.NoError(err)
			require.NotNil(orig)

			if tt.chgFn != nil {
				orig = tt.chgFn(orig)
			}
			var version uint32
			if orig != nil {
				version = orig.GetVersion()
			}
			got, gotCount, err := repo.UpdateSshPrivateKeyCredential(ctx, prj.GetPublicId(), orig, version, tt.masks)
			if tt.wantErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantErr), err), "want err: %q got: %q", tt.wantErr, err)
				assert.Equal(tt.wantCount, gotCount, "row count")
				assert.Nil(got)
				return
			}
			assert.NoError(err)
			assert.Empty(tt.orig.PublicId)
			require.NotNil(got)
			assertPublicId(t, globals.SshPrivateKeyCredentialPrefix, got.PublicId)
			assert.Equal(tt.wantCount, gotCount, "row count")
			assert.NotSame(tt.orig, got)
			assert.Equal(tt.orig.StoreId, got.StoreId)
			underlyingDB, err := conn.SqlDB(ctx)
			require.NoError(err)
			dbassert := dbassert.New(t, underlyingDB)
			if tt.want.Name == "" {
				got := got.clone()
				dbassert.IsNull(got, "name")
			} else {
				assert.Equal(tt.want.Name, got.Name)
			}

			if tt.want.Description == "" {
				got := got.clone()
				dbassert.IsNull(got, "description")
			} else {
				assert.Equal(tt.want.Description, got.Description)
			}

			assert.Equal(tt.want.Username, got.Username)

			// Validate only PrivateKeyHmac is returned
			assert.Empty(got.PrivateKey)
			assert.Empty(got.PrivateKeyEncrypted)
			assert.NotEmpty(got.PrivateKeyHmac)

			// Validate hmac
			databaseWrapper, err := kkms.GetWrapper(context.Background(), prj.GetPublicId(), kms.KeyPurposeDatabase)
			require.NoError(err)
			hm, err := crypto.HmacSha256(ctx, tt.want.PrivateKey, databaseWrapper, []byte(store.GetPublicId()), nil)
			require.NoError(err)
			assert.Equal([]byte(hm), got.PrivateKeyHmac)

			if tt.wantCount > 0 {
				assert.NoError(db.TestVerifyOplog(t, rw, got.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second)))
			}
		})
	}
}

func TestSshPrivateKeyConstraints(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kkms := kms.TestKms(t, conn, wrapper)
	repo, err := NewRepository(ctx, rw, rw, kkms)

	assert, require := assert.New(t), require.New(t)
	assert.NoError(err)
	require.NotNil(repo)

	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	store := TestCredentialStore(t, conn, wrapper, prj.GetPublicId())

	// Base case: should work fine
	cred, err := NewSshPrivateKeyCredential(
		ctx,
		store.PublicId,
		"foobar",
		credential.PrivateKey(testdata.PEMEncryptedKeys[0].PEMBytes),
		WithPrivateKeyPassphrase([]byte(testdata.PEMEncryptedKeys[0].EncryptionKey)))
	require.NoError(err)
	cred.PublicId, err = credential.NewSshPrivateKeyCredentialId(ctx)
	require.NoError(err)
	databaseWrapper, err := kkms.GetWrapper(ctx, prj.PublicId, kms.KeyPurposeDatabase)
	require.NoError(cred.encrypt(ctx, databaseWrapper))

	tests := []struct {
		name         string
		nilEncrypted bool
		nilHmac      bool
	}{
		{
			name: "valid",
		},
		{
			name:         "nil-encrypted",
			nilEncrypted: true,
		},
		{
			name:    "nil-hmac",
			nilHmac: true,
		},
		{
			name:         "valid-both-nil",
			nilEncrypted: true,
			nilHmac:      true,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			c := cred.clone()
			if tt.nilEncrypted {
				c.PrivateKeyPassphraseEncrypted = nil
			}
			if tt.nilHmac {
				c.PrivateKeyPassphraseHmac = nil
			}
			c.PublicId, err = credential.NewSshPrivateKeyCredentialId(ctx)
			require.NoError(err)
			err := rw.Create(ctx, c)
			switch {
			case !tt.nilEncrypted && !tt.nilHmac, tt.nilEncrypted && tt.nilHmac:
				assert.NoError(err)
			default:
				assert.Error(err)
			}
		})
	}
}

func TestRepository_UpdateJsonCredential(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)

	_, objBytes := TestJsonObject(t)

	secondJsonSecret := &structpb.Struct{
		Fields: map[string]*structpb.Value{
			"username": structpb.NewStringValue("new-user"),
			"password": structpb.NewStringValue("new-password"),
			"hash":     structpb.NewStringValue("0987654321"),
		},
	}
	secondBSecret, err := json.Marshal(secondJsonSecret)
	assert.NoError(t, err)

	changeName := func(n string) func(credential *JsonCredential) *JsonCredential {
		return func(c *JsonCredential) *JsonCredential {
			c.Name = n
			return c
		}
	}

	changeDescription := func(d string) func(*JsonCredential) *JsonCredential {
		return func(c *JsonCredential) *JsonCredential {
			c.Description = d
			return c
		}
	}

	makeNil := func() func(*JsonCredential) *JsonCredential {
		return func(_ *JsonCredential) *JsonCredential {
			return nil
		}
	}

	makeEmbeddedNil := func() func(*JsonCredential) *JsonCredential {
		return func(_ *JsonCredential) *JsonCredential {
			return &JsonCredential{}
		}
	}

	setPublicId := func(n string) func(*JsonCredential) *JsonCredential {
		return func(c *JsonCredential) *JsonCredential {
			c.PublicId = n
			return c
		}
	}

	deleteStoreId := func() func(*JsonCredential) *JsonCredential {
		return func(c *JsonCredential) *JsonCredential {
			c.StoreId = ""
			return c
		}
	}

	deleteVersion := func() func(*JsonCredential) *JsonCredential {
		return func(c *JsonCredential) *JsonCredential {
			c.Version = 0
			return c
		}
	}

	changeObject := func(s []byte) func(*JsonCredential) *JsonCredential {
		return func(c *JsonCredential) *JsonCredential {
			c.Object = s
			return c
		}
	}

	combine := func(fns ...func(cs *JsonCredential) *JsonCredential) func(*JsonCredential) *JsonCredential {
		return func(c *JsonCredential) *JsonCredential {
			for _, fn := range fns {
				c = fn(c)
			}
			return c
		}
	}

	tests := []struct {
		name      string
		orig      *JsonCredential
		chgFn     func(*JsonCredential) *JsonCredential
		masks     []string
		want      *JsonCredential
		wantCount int
		wantErr   errors.Code
	}{
		{
			name: "nil-credential",
			orig: &JsonCredential{
				JsonCredential: &store.JsonCredential{
					Object: objBytes,
				},
			},
			chgFn:   makeNil(),
			masks:   []string{"Name", "Description"},
			wantErr: errors.InvalidParameter,
		},
		{
			name: "nil-embedded-credential",
			orig: &JsonCredential{
				JsonCredential: &store.JsonCredential{
					Object: objBytes,
				},
			},
			chgFn:   makeEmbeddedNil(),
			masks:   []string{"Name", "Description"},
			wantErr: errors.InvalidParameter,
		},
		{
			name: "no-public-id",
			orig: &JsonCredential{
				JsonCredential: &store.JsonCredential{
					Object: objBytes,
				},
			},
			chgFn:   setPublicId(""),
			masks:   []string{"Name", "Description"},
			wantErr: errors.InvalidPublicId,
		},
		{
			name: "no-store-id",
			orig: &JsonCredential{
				JsonCredential: &store.JsonCredential{
					Object: objBytes,
				},
			},
			chgFn:   deleteStoreId(),
			masks:   []string{"Name", "Description"},
			wantErr: errors.InvalidParameter,
		},
		{
			name: "no-version",
			orig: &JsonCredential{
				JsonCredential: &store.JsonCredential{
					Object: objBytes,
				},
			},
			chgFn:   deleteVersion(),
			masks:   []string{"Name", "Description"},
			wantErr: errors.InvalidParameter,
		},
		{
			name: "updating-non-existent-credential",
			orig: &JsonCredential{
				JsonCredential: &store.JsonCredential{
					Name:   "test-name-repo",
					Object: objBytes,
				},
			},
			chgFn:   combine(setPublicId("abcd_OOOOOOOOOO"), changeName("test-update-name-repo")),
			masks:   []string{"Name"},
			wantErr: errors.RecordNotFound,
		},
		{
			name: "empty-field-mask",
			orig: &JsonCredential{
				JsonCredential: &store.JsonCredential{
					Name:   "test-name-repo",
					Object: objBytes,
				},
			},
			chgFn:   changeName("test-update-name-repo"),
			wantErr: errors.EmptyFieldMask,
		},
		{
			name: "read-only-fields-in-field-mask",
			orig: &JsonCredential{
				JsonCredential: &store.JsonCredential{
					Name:   "test-name-repo",
					Object: objBytes,
				},
			},
			chgFn:   changeName("test-update-name-repo"),
			masks:   []string{"PublicId", "CreateTime", "UpdateTime", "ScopeId"},
			wantErr: errors.InvalidFieldMask,
		},
		{
			name: "unknown-field-in-field-mask",
			orig: &JsonCredential{
				JsonCredential: &store.JsonCredential{
					Name:   "test-name-repo",
					Object: objBytes,
				},
			},
			chgFn:   changeName("test-update-name-repo"),
			masks:   []string{"FIELD_DNE"},
			wantErr: errors.InvalidFieldMask,
		},
		{
			name: "change-name",
			orig: &JsonCredential{
				JsonCredential: &store.JsonCredential{
					Name:   "test-name-repo",
					Object: objBytes,
				},
			},
			chgFn: changeName("test-update-name-repo"),
			masks: []string{"Name"},
			want: &JsonCredential{
				JsonCredential: &store.JsonCredential{
					Name:   "test-update-name-repo",
					Object: objBytes,
				},
			},
			wantCount: 1,
		},
		{
			name: "change-description",
			orig: &JsonCredential{
				JsonCredential: &store.JsonCredential{
					Description: "test-description-repo",
					Object:      objBytes,
				},
			},
			chgFn: changeDescription("test-update-description-repo"),
			masks: []string{"Description"},
			want: &JsonCredential{
				JsonCredential: &store.JsonCredential{
					Description: "test-update-description-repo",
					Object:      objBytes,
				},
			},
			wantCount: 1,
		},
		{
			name: "change-name-and-description",
			orig: &JsonCredential{
				JsonCredential: &store.JsonCredential{
					Name:        "test-name-repo",
					Description: "test-description-repo",
					Object:      objBytes,
				},
			},
			chgFn: combine(changeDescription("test-update-description-repo"), changeName("test-update-name-repo")),
			masks: []string{"Name", "Description"},
			want: &JsonCredential{
				JsonCredential: &store.JsonCredential{
					Name:        "test-update-name-repo",
					Description: "test-update-description-repo",
					Object:      objBytes,
				},
			},
			wantCount: 1,
		},
		{
			name: "change-json-secret",
			orig: &JsonCredential{
				JsonCredential: &store.JsonCredential{
					Object: objBytes,
				},
			},
			chgFn: changeObject(secondBSecret),
			masks: []string{"attributes.object.username", "attributes.object.password", "attributes.object.hash"},
			want: &JsonCredential{
				JsonCredential: &store.JsonCredential{
					Object: secondBSecret,
				},
			},
			wantCount: 1,
		},
		{
			name: "do-not-delete-json-secret",
			orig: &JsonCredential{
				JsonCredential: &store.JsonCredential{
					Object: objBytes,
				},
			},
			masks: []string{},
			chgFn: changeObject(nil),
			want: &JsonCredential{
				JsonCredential: &store.JsonCredential{
					Object: objBytes,
				},
			},
			wantErr:   errors.EmptyFieldMask,
			wantCount: 0,
		},
		{
			name: "delete-name",
			orig: &JsonCredential{
				JsonCredential: &store.JsonCredential{
					Name:        "test-name-repo",
					Description: "test-description-repo",
					Object:      objBytes,
				},
			},
			masks: []string{"Name"},
			chgFn: combine(changeDescription("test-update-description-repo"), changeName("")),
			want: &JsonCredential{
				JsonCredential: &store.JsonCredential{
					Description: "test-description-repo",
					Object:      objBytes,
				},
			},
			wantCount: 1,
		},
		{
			name: "delete-description",
			orig: &JsonCredential{
				JsonCredential: &store.JsonCredential{
					Name:        "test-name-repo",
					Description: "test-description-repo",
					Object:      objBytes,
				},
			},
			masks: []string{"Description"},
			chgFn: combine(changeDescription(""), changeName("test-update-name-repo")),
			want: &JsonCredential{
				JsonCredential: &store.JsonCredential{
					Name:   "test-name-repo",
					Object: objBytes,
				},
			},
			wantCount: 1,
		},
		{
			name: "do-not-delete-name",
			orig: &JsonCredential{
				JsonCredential: &store.JsonCredential{
					Name:        "test-name-repo",
					Description: "test-description-repo",
					Object:      objBytes,
				},
			},
			masks: []string{"Description"},
			chgFn: combine(changeDescription("test-update-description-repo"), changeName("")),
			want: &JsonCredential{
				JsonCredential: &store.JsonCredential{
					Name:        "test-name-repo",
					Description: "test-update-description-repo",
					Object:      objBytes,
				},
			},
			wantCount: 1,
		},
		{
			name: "do-not-delete-description",
			orig: &JsonCredential{
				JsonCredential: &store.JsonCredential{
					Name:        "test-name-repo",
					Description: "test-description-repo",
					Object:      objBytes,
				},
			},
			masks: []string{"Name"},
			chgFn: combine(changeDescription(""), changeName("test-update-name-repo")),
			want: &JsonCredential{
				JsonCredential: &store.JsonCredential{
					Name:        "test-update-name-repo",
					Description: "test-description-repo",
					Object:      objBytes,
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
			kkms := kms.TestKms(t, conn, wrapper)
			repo, err := NewRepository(ctx, rw, rw, kkms)
			assert.NoError(err)
			require.NotNil(repo)

			_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
			store := TestCredentialStore(t, conn, wrapper, prj.GetPublicId())
			tt.orig.StoreId = store.PublicId

			orig, err := repo.CreateJsonCredential(ctx, prj.GetPublicId(), tt.orig)
			assert.NoError(err)
			require.NotNil(orig)

			if tt.chgFn != nil {
				orig = tt.chgFn(orig)
			}
			var version uint32
			if orig != nil {
				version = orig.GetVersion()
			}
			got, gotCount, err := repo.UpdateJsonCredential(ctx, prj.GetPublicId(), orig, version, tt.masks)
			if tt.wantErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantErr), err), "want err: %q got: %q", tt.wantErr, err)
				assert.Equal(tt.wantCount, gotCount, "row count")
				assert.Nil(got)
				return
			}
			assert.NoError(err)
			assert.Empty(tt.orig.PublicId)
			require.NotNil(got)
			assertPublicId(t, globals.JsonCredentialPrefix, got.PublicId)
			assert.Equal(tt.wantCount, gotCount, "row count")
			assert.NotSame(tt.orig, got)
			assert.Equal(tt.orig.StoreId, got.StoreId)
			underlyingDB, err := conn.SqlDB(ctx)
			require.NoError(err)
			dbassert := dbassert.New(t, underlyingDB)
			if tt.want.Name == "" {
				got := got.clone()
				dbassert.IsNull(got, "name")
			} else {
				assert.Equal(tt.want.Name, got.Name)
			}

			if tt.want.Description == "" {
				got := got.clone()
				dbassert.IsNull(got, "description")
			} else {
				assert.Equal(tt.want.Description, got.Description)
			}

			// Validate only SecretHmac is returned
			assert.Empty(got.Object)
			assert.Empty(got.ObjectEncrypted)
			assert.NotEmpty(got.ObjectHmac)

			// Validate hmac
			databaseWrapper, err := kkms.GetWrapper(context.Background(), prj.GetPublicId(), kms.KeyPurposeDatabase)
			require.NoError(err)
			hm, err := crypto.HmacSha256(ctx, tt.want.Object, databaseWrapper, []byte(store.GetPublicId()), nil)
			require.NoError(err)
			assert.Equal([]byte(hm), got.ObjectHmac)

			if tt.wantCount > 0 {
				assert.NoError(db.TestVerifyOplog(t, rw, got.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second)))
			}
		})
	}
}

func TestRepository_ListDeletedCredentialIds(t *testing.T) {
	t.Parallel()
	assert, require := assert.New(t), require.New(t)
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	store := TestCredentialStore(t, conn, wrapper, prj.GetPublicId())
	obj, _ := TestJsonObject(t)
	jsonCreds := TestJsonCredentials(t, conn, wrapper, store.GetPublicId(), prj.GetPublicId(), obj, 2)
	sshCreds := TestSshPrivateKeyCredentials(t, conn, wrapper, "username", TestSshPrivateKeyPem, store.GetPublicId(), prj.GetPublicId(), 2)
	pwCreds := TestUsernamePasswordCredentials(t, conn, wrapper, "username", "testpassword", store.GetPublicId(), prj.GetPublicId(), 2)
	updCreds := TestUsernamePasswordDomainCredentials(t, conn, wrapper, "username", "testpassword", "domain", store.GetPublicId(), prj.GetPublicId(), 2)
	pCreds := TestPasswordCredentials(t, conn, wrapper, "testpassword", store.GetPublicId(), prj.GetPublicId(), 2)

	repo, err := NewRepository(ctx, rw, rw, kms)
	require.NoError(err)
	require.NotNil(repo)
	staticRepo, err := NewRepository(ctx, rw, rw, kms)
	require.NoError(err)

	// Expect no entries at the start
	deletedIds, ttime, err := repo.ListDeletedCredentialIds(ctx, time.Now().AddDate(-1, 0, 0))
	require.NoError(err)
	require.Empty(deletedIds)
	// Expect transaction timestamp to be within ~10 seconds of now
	require.True(time.Now().Before(ttime.Add(10 * time.Second)))
	require.True(time.Now().After(ttime.Add(-10 * time.Second)))

	// Delete a json credential
	_, err = staticRepo.DeleteCredential(ctx, prj.GetPublicId(), jsonCreds[0].GetPublicId())
	require.NoError(err)

	// Expect one entry
	deletedIds, ttime, err = repo.ListDeletedCredentialIds(ctx, time.Now().AddDate(-1, 0, 0))
	require.NoError(err)
	assert.Empty(
		cmp.Diff(
			[]string{jsonCreds[0].GetPublicId()},
			deletedIds,
			cmpopts.SortSlices(func(i, j string) bool { return i < j }),
		),
	)
	require.True(time.Now().Before(ttime.Add(10 * time.Second)))
	require.True(time.Now().After(ttime.Add(-10 * time.Second)))

	// Delete a ssh credential
	_, err = staticRepo.DeleteCredential(ctx, prj.GetPublicId(), sshCreds[0].GetPublicId())
	require.NoError(err)

	// Expect two entries
	deletedIds, ttime, err = repo.ListDeletedCredentialIds(ctx, time.Now().AddDate(-1, 0, 0))
	require.NoError(err)
	assert.Empty(
		cmp.Diff(
			[]string{jsonCreds[0].GetPublicId(), sshCreds[0].GetPublicId()},
			deletedIds,
			cmpopts.SortSlices(func(i, j string) bool { return i < j }),
		),
	)
	require.True(time.Now().Before(ttime.Add(10 * time.Second)))
	require.True(time.Now().After(ttime.Add(-10 * time.Second)))

	// Delete a pw credential
	_, err = staticRepo.DeleteCredential(ctx, prj.GetPublicId(), pwCreds[0].GetPublicId())
	require.NoError(err)

	// Expect three entries
	deletedIds, ttime, err = repo.ListDeletedCredentialIds(ctx, time.Now().AddDate(-1, 0, 0))
	require.NoError(err)
	assert.Empty(
		cmp.Diff(
			[]string{jsonCreds[0].GetPublicId(), sshCreds[0].GetPublicId(), pwCreds[0].GetPublicId()},
			deletedIds,
			cmpopts.SortSlices(func(i, j string) bool { return i < j }),
		),
	)
	require.True(time.Now().Before(ttime.Add(10 * time.Second)))
	require.True(time.Now().After(ttime.Add(-10 * time.Second)))

	// Delete a upd credential
	_, err = staticRepo.DeleteCredential(ctx, prj.GetPublicId(), updCreds[0].GetPublicId())
	require.NoError(err)

	// Expect four entries
	deletedIds, ttime, err = repo.ListDeletedCredentialIds(ctx, time.Now().AddDate(-1, 0, 0))
	require.NoError(err)
	assert.Empty(
		cmp.Diff(
			[]string{jsonCreds[0].GetPublicId(), sshCreds[0].GetPublicId(), pwCreds[0].GetPublicId(), updCreds[0].GetPublicId()},
			deletedIds,
			cmpopts.SortSlices(func(i, j string) bool { return i < j }),
		),
	)
	require.True(time.Now().Before(ttime.Add(10 * time.Second)))
	require.True(time.Now().After(ttime.Add(-10 * time.Second)))

	// Delete a p credential
	_, err = staticRepo.DeleteCredential(ctx, prj.GetPublicId(), pCreds[0].GetPublicId())
	require.NoError(err)

	// Expect five entries
	deletedIds, ttime, err = repo.ListDeletedCredentialIds(ctx, time.Now().AddDate(-1, 0, 0))
	require.NoError(err)
	assert.Empty(
		cmp.Diff(
			[]string{jsonCreds[0].GetPublicId(), sshCreds[0].GetPublicId(), pwCreds[0].GetPublicId(), updCreds[0].GetPublicId(), pCreds[0].GetPublicId()},
			deletedIds,
			cmpopts.SortSlices(func(i, j string) bool { return i < j }),
		),
	)
	require.True(time.Now().Before(ttime.Add(10 * time.Second)))
	require.True(time.Now().After(ttime.Add(-10 * time.Second)))

	// Try again with the time set to now, expect no entries
	deletedIds, ttime, err = repo.ListDeletedCredentialIds(ctx, time.Now())
	require.NoError(err)
	require.Empty(deletedIds)
	require.True(time.Now().Before(ttime.Add(10 * time.Second)))
	require.True(time.Now().After(ttime.Add(-10 * time.Second)))
}

func TestRepository_EstimatedCredentialCount(t *testing.T) {
	t.Parallel()
	assert, require := assert.New(t), require.New(t)
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	sqlDb, err := conn.SqlDB(ctx)
	require.NoError(err)
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	staticStore := TestCredentialStore(t, conn, wrapper, prj.GetPublicId())

	repo, err := NewRepository(ctx, rw, rw, kms)
	require.NoError(err)
	require.NotNil(repo)
	staticRepo, err := NewRepository(ctx, rw, rw, kms)
	require.NoError(err)

	// Check total entries at start, expect 0
	numItems, err := repo.EstimatedCredentialCount(ctx)
	require.NoError(err)
	assert.Equal(0, numItems)

	// Create some credentials
	obj, _ := TestJsonObject(t)
	assert.NoError(err)
	jsonCreds := TestJsonCredentials(t, conn, wrapper, staticStore.GetPublicId(), prj.GetPublicId(), obj, 2)
	sshCreds := TestSshPrivateKeyCredentials(t, conn, wrapper, "username", TestSshPrivateKeyPem, staticStore.GetPublicId(), prj.GetPublicId(), 2)
	pwCreds := TestUsernamePasswordCredentials(t, conn, wrapper, "username", "testpassword", staticStore.GetPublicId(), prj.GetPublicId(), 2)
	updCreds := TestUsernamePasswordDomainCredentials(t, conn, wrapper, "username", "testpassword", "domain", staticStore.GetPublicId(), prj.GetPublicId(), 2)
	pCreds := TestPasswordCredentials(t, conn, wrapper, "testpassword", staticStore.GetPublicId(), prj.GetPublicId(), 2)
	// Run analyze to update postgres meta tables
	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(err)

	numItems, err = repo.EstimatedCredentialCount(ctx)
	require.NoError(err)
	assert.Equal(10, numItems)

	// Delete a json credential
	_, err = staticRepo.DeleteCredential(ctx, prj.GetPublicId(), jsonCreds[0].GetPublicId())
	require.NoError(err)
	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(err)

	numItems, err = repo.EstimatedCredentialCount(ctx)
	require.NoError(err)
	assert.Equal(9, numItems)

	// Delete a ssh credential
	_, err = staticRepo.DeleteCredential(ctx, prj.GetPublicId(), sshCreds[0].GetPublicId())
	require.NoError(err)
	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(err)

	numItems, err = repo.EstimatedCredentialCount(ctx)
	require.NoError(err)
	assert.Equal(8, numItems)

	// Delete a pw credential
	_, err = staticRepo.DeleteCredential(ctx, prj.GetPublicId(), pwCreds[0].GetPublicId())
	require.NoError(err)
	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(err)

	numItems, err = repo.EstimatedCredentialCount(ctx)
	require.NoError(err)
	assert.Equal(7, numItems)

	// Delete a upd credential
	_, err = staticRepo.DeleteCredential(ctx, prj.GetPublicId(), updCreds[0].GetPublicId())
	require.NoError(err)
	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(err)

	numItems, err = repo.EstimatedCredentialCount(ctx)
	require.NoError(err)
	assert.Equal(6, numItems)

	// Delete a p credential
	_, err = staticRepo.DeleteCredential(ctx, prj.GetPublicId(), pCreds[0].GetPublicId())
	require.NoError(err)
	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(err)

	numItems, err = repo.EstimatedCredentialCount(ctx)
	require.NoError(err)
	assert.Equal(5, numItems)
}
