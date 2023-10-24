// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package static

import (
	"context"
	"encoding/json"
	"testing"
	"time"

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
		got3, err := repo.CreateUsernamePasswordCredential(ctx, prj2.GetPublicId(), in3)
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
	total := 30
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	store := TestCredentialStore(t, conn, wrapper, prj.GetPublicId())
	TestUsernamePasswordCredentials(t, conn, wrapper, "user", "pass", store.GetPublicId(), prj.GetPublicId(), total/3)
	TestSshPrivateKeyCredentials(t, conn, wrapper, "user", TestSshPrivateKeyPem, store.GetPublicId(), prj.GetPublicId(), total/3)

	obj, _ := TestJsonObject(t)

	TestJsonCredentials(t, conn, wrapper, store.GetPublicId(), prj.GetPublicId(), obj, total/3)

	type args struct {
		storeId string
		opt     []Option
	}
	tests := []struct {
		name    string
		args    args
		wantCnt int
	}{
		{
			name: "no-limit",
			args: args{
				storeId: store.PublicId,
				opt:     []Option{WithLimit(-1)},
			},
			wantCnt: total,
		},
		{
			name: "default-limit",
			args: args{
				storeId: store.PublicId,
			},
			wantCnt: defaultLimit * 3,
		},
		{
			name: "custom-limit",
			args: args{
				storeId: store.PublicId,
				opt:     []Option{WithLimit(3)},
			},
			wantCnt: 9,
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

			got, err := repo.ListCredentials(context.Background(), tt.args.storeId, tt.args.opt...)
			require.NoError(err)
			assert.Equal(tt.wantCnt, len(got))

			// Validate only hmac values are returned
			for _, c := range got {
				switch v := c.(type) {
				case *UsernamePasswordCredential:
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
