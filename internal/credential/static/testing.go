// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package static

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/kms"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	TestSshPrivateKeyPem = `
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDxfwhEAZKrnsbQxOjVA3PFiB3bW3tSpNKx8TdMiCqlzQAAAJDmpbfr5qW3
6wAAAAtzc2gtZWQyNTUxOQAAACDxfwhEAZKrnsbQxOjVA3PFiB3bW3tSpNKx8TdMiCqlzQ
AAAEBvvkQkH06ad2GpX1VVARzu9NkHA6gzamAaQ/hkn5FuZvF/CEQBkquextDE6NUDc8WI
Hdtbe1Kk0rHxN0yIKqXNAAAACWplZmZAYXJjaAECAwQ=
-----END OPENSSH PRIVATE KEY-----
`
	TestLargeSshPrivateKeyPem = `
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
`
)

// TestJsonObject returns a json object and it's marshalled format to be used for testing
func TestJsonObject(t testing.TB) (credential.JsonObject, []byte) {
	object := credential.JsonObject{
		Struct: &structpb.Struct{
			Fields: map[string]*structpb.Value{
				"username": structpb.NewStringValue("user"),
				"password": structpb.NewStringValue("password"),
				"hash":     structpb.NewStringValue("1234567890"),
			},
		},
	}
	b, err := json.Marshal(object.AsMap())
	require.NoError(t, err)
	return object, b
}

// TestCredentialStore creates a static credential store in the provided DB with
// the provided project id and any values passed in through the Options vars.
// If any errors are encountered during the creation of the store, the test will fail.
func TestCredentialStore(t testing.TB, conn *db.DB, wrapper wrapping.Wrapper, projectId string, opts ...Option) *CredentialStore {
	t.Helper()
	ctx := context.Background()
	kmsCache := kms.TestKms(t, conn, wrapper)
	w := db.New(conn)

	databaseWrapper, err := kmsCache.GetWrapper(ctx, projectId, kms.KeyPurposeDatabase)
	assert.NoError(t, err)
	require.NotNil(t, databaseWrapper)

	cs, err := NewCredentialStore(projectId, opts...)
	assert.NoError(t, err)
	require.NotNil(t, cs)

	opt := getOpts(opts...)
	id := opt.withPublicId
	if id == "" {
		id, err = newCredentialStoreId(ctx)
		assert.NoError(t, err)
		require.NotEmpty(t, id)
	}
	cs.PublicId = id

	_, err2 := w.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(_ db.Reader, iw db.Writer) error {
			require.NoError(t, iw.Create(ctx, cs))
			return nil
		},
	)
	require.NoError(t, err2)

	return cs
}

// TestCredentialStores creates count number of static credential stores in
// the provided DB with the provided project id. If any errors are
// encountered during the creation of the credential stores, the test will
// fail.
func TestCredentialStores(t testing.TB, conn *db.DB, wrapper wrapping.Wrapper, projectId string, count int) []*CredentialStore {
	t.Helper()
	ctx := context.Background()
	kmsCache := kms.TestKms(t, conn, wrapper)

	databaseWrapper, err := kmsCache.GetWrapper(ctx, projectId, kms.KeyPurposeDatabase)
	assert.NoError(t, err)
	require.NotNil(t, databaseWrapper)

	css := make([]*CredentialStore, 0, count)
	for i := 0; i < count; i++ {
		css = append(css, TestCredentialStore(t, conn, wrapper, projectId))
	}
	return css
}

// TestUsernamePasswordCredential creates a username password credential in the provided DB with
// the provided project id and any values passed in through.
// If any errors are encountered during the creation of the store, the test will fail.
func TestUsernamePasswordCredential(
	t testing.TB,
	conn *db.DB,
	wrapper wrapping.Wrapper,
	username, password, storeId, projectId string,
	opts ...Option,
) *UsernamePasswordCredential {
	t.Helper()
	ctx := context.Background()
	kmsCache := kms.TestKms(t, conn, wrapper)
	w := db.New(conn)

	opt := getOpts(opts...)

	databaseWrapper, err := kmsCache.GetWrapper(ctx, projectId, kms.KeyPurposeDatabase)
	assert.NoError(t, err)
	require.NotNil(t, databaseWrapper)

	cred, err := NewUsernamePasswordCredential(storeId, username, credential.Password(password), opts...)
	require.NoError(t, err)
	require.NotNil(t, cred)

	id := opt.withPublicId
	if id == "" {
		id, err = credential.NewUsernamePasswordCredentialId(ctx)
		require.NoError(t, err)
	}
	cred.PublicId = id

	err = cred.encrypt(ctx, databaseWrapper)
	require.NoError(t, err)

	_, err2 := w.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(_ db.Reader, iw db.Writer) error {
			require.NoError(t, iw.Create(ctx, cred))
			return nil
		},
	)
	require.NoError(t, err2)

	return cred
}

// TestUsernamePasswordCredentials creates count number of username password credentials in
// the provided DB with the provided project id. If any errors are
// encountered during the creation of the credentials, the test will fail.
func TestUsernamePasswordCredentials(
	t testing.TB,
	conn *db.DB,
	wrapper wrapping.Wrapper,
	username, password, storeId, projectId string,
	count int,
) []*UsernamePasswordCredential {
	t.Helper()
	ctx := context.Background()
	kmsCache := kms.TestKms(t, conn, wrapper)

	databaseWrapper, err := kmsCache.GetWrapper(ctx, projectId, kms.KeyPurposeDatabase)
	assert.NoError(t, err)
	require.NotNil(t, databaseWrapper)

	creds := make([]*UsernamePasswordCredential, 0, count)
	for i := 0; i < count; i++ {
		creds = append(creds, TestUsernamePasswordCredential(t, conn, wrapper, username, password, storeId, projectId))
	}
	return creds
}

// TestUsernamePasswordDomainCredential creates a username password domain credential in the provided DB with
// the provided project id and any values passed in through.
// If any errors are encountered during the creation of the store, the test will fail.
func TestUsernamePasswordDomainCredential(
	t testing.TB,
	conn *db.DB,
	wrapper wrapping.Wrapper,
	username, password, domain, storeId, projectId string,
	opts ...Option,
) *UsernamePasswordDomainCredential {
	t.Helper()
	ctx := context.Background()
	kmsCache := kms.TestKms(t, conn, wrapper)
	w := db.New(conn)

	opt := getOpts(opts...)

	databaseWrapper, err := kmsCache.GetWrapper(ctx, projectId, kms.KeyPurposeDatabase)
	assert.NoError(t, err)
	require.NotNil(t, databaseWrapper)

	cred, err := NewUsernamePasswordDomainCredential(storeId, username, credential.Password(password), domain, opts...)
	require.NoError(t, err)
	require.NotNil(t, cred)

	id := opt.withPublicId
	if id == "" {
		id, err = credential.NewUsernamePasswordDomainCredentialId(ctx)
		require.NoError(t, err)
	}
	cred.PublicId = id

	err = cred.encrypt(ctx, databaseWrapper)
	require.NoError(t, err)

	_, err2 := w.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(_ db.Reader, iw db.Writer) error {
			require.NoError(t, iw.Create(ctx, cred))
			return nil
		},
	)
	require.NoError(t, err2)

	return cred
}

// TestUsernamePasswordDomainCredentials creates count number of username password domain credentials in
// the provided DB with the provided project id. If any errors are
// encountered during the creation of the credentials, the test will fail.
func TestUsernamePasswordDomainCredentials(
	t testing.TB,
	conn *db.DB,
	wrapper wrapping.Wrapper,
	username, password, domain, storeId, projectId string,
	count int,
) []*UsernamePasswordDomainCredential {
	t.Helper()
	ctx := context.Background()
	kmsCache := kms.TestKms(t, conn, wrapper)

	databaseWrapper, err := kmsCache.GetWrapper(ctx, projectId, kms.KeyPurposeDatabase)
	assert.NoError(t, err)
	require.NotNil(t, databaseWrapper)

	creds := make([]*UsernamePasswordDomainCredential, 0, count)
	for i := 0; i < count; i++ {
		creds = append(creds, TestUsernamePasswordDomainCredential(t, conn, wrapper, username, password, domain, storeId, projectId))
	}
	return creds
}

// TestPasswordCredential creates a password credential in the provided DB with
// the provided project id and any values passed in through.
// If any errors are encountered during the creation of the store, the test will fail.
func TestPasswordCredential(
	t testing.TB,
	conn *db.DB,
	wrapper wrapping.Wrapper,
	password, storeId, projectId string,
	opts ...Option,
) *PasswordCredential {
	t.Helper()
	ctx := context.Background()
	kmsCache := kms.TestKms(t, conn, wrapper)
	w := db.New(conn)

	opt := getOpts(opts...)

	databaseWrapper, err := kmsCache.GetWrapper(ctx, projectId, kms.KeyPurposeDatabase)
	assert.NoError(t, err)
	require.NotNil(t, databaseWrapper)

	cred, err := NewPasswordCredential(storeId, credential.Password(password), opts...)
	require.NoError(t, err)
	require.NotNil(t, cred)

	id := opt.withPublicId
	if id == "" {
		id, err = credential.NewPasswordCredentialId(ctx)
		require.NoError(t, err)
	}
	cred.PublicId = id

	err = cred.encrypt(ctx, databaseWrapper)
	require.NoError(t, err)

	_, err2 := w.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(_ db.Reader, iw db.Writer) error {
			require.NoError(t, iw.Create(ctx, cred))
			return nil
		},
	)
	require.NoError(t, err2)

	return cred
}

// TestPasswordCredentials creates count number of password credentials in
// the provided DB with the provided project id. If any errors are
// encountered during the creation of the credentials, the test will fail.
func TestPasswordCredentials(
	t testing.TB,
	conn *db.DB,
	wrapper wrapping.Wrapper,
	password, storeId, projectId string,
	count int,
) []*PasswordCredential {
	t.Helper()
	ctx := context.Background()
	kmsCache := kms.TestKms(t, conn, wrapper)

	databaseWrapper, err := kmsCache.GetWrapper(ctx, projectId, kms.KeyPurposeDatabase)
	assert.NoError(t, err)
	require.NotNil(t, databaseWrapper)

	creds := make([]*PasswordCredential, 0, count)
	for i := 0; i < count; i++ {
		creds = append(creds, TestPasswordCredential(t, conn, wrapper, password, storeId, projectId))
	}
	return creds
}

// TestSshPrivateKeyCredential creates an ssh private key credential in the
// provided DB with the provided project and any values passed in through. If any
// errors are encountered during the creation of the store, the test will fail.
func TestSshPrivateKeyCredential(
	t testing.TB,
	conn *db.DB,
	wrapper wrapping.Wrapper,
	username, privateKey, storeId, projectId string,
	opt ...Option,
) *SshPrivateKeyCredential {
	t.Helper()
	ctx := context.Background()
	kmsCache := kms.TestKms(t, conn, wrapper)
	w := db.New(conn)

	opts := getOpts(opt...)

	databaseWrapper, err := kmsCache.GetWrapper(ctx, projectId, kms.KeyPurposeDatabase)
	assert.NoError(t, err)
	require.NotNil(t, databaseWrapper)

	cred, err := NewSshPrivateKeyCredential(ctx, storeId, username, credential.PrivateKey(privateKey), opt...)
	require.NoError(t, err)
	require.NotNil(t, cred)

	id := opts.withPublicId
	if id == "" {
		id, err = credential.NewSshPrivateKeyCredentialId(ctx)
		require.NoError(t, err)
	}
	cred.PublicId = id

	err = cred.encrypt(ctx, databaseWrapper)
	require.NoError(t, err)

	_, err2 := w.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(_ db.Reader, iw db.Writer) error {
			require.NoError(t, iw.Create(ctx, cred))
			return nil
		},
	)
	require.NoError(t, err2)

	return cred
}

// TestSshPrivateKeyCredentials creates count number of ssh private key
// credentials in the provided DB with the provided project id. If any errors are
// encountered during the creation of the credentials, the test will fail.
func TestSshPrivateKeyCredentials(
	t testing.TB,
	conn *db.DB,
	wrapper wrapping.Wrapper,
	username, privateKey, storeId, projectId string,
	count int,
) []*SshPrivateKeyCredential {
	t.Helper()
	ctx := context.Background()
	kmsCache := kms.TestKms(t, conn, wrapper)

	databaseWrapper, err := kmsCache.GetWrapper(ctx, projectId, kms.KeyPurposeDatabase)
	assert.NoError(t, err)
	require.NotNil(t, databaseWrapper)

	creds := make([]*SshPrivateKeyCredential, 0, count)
	for i := 0; i < count; i++ {
		creds = append(creds, TestSshPrivateKeyCredential(t, conn, wrapper, username, privateKey, storeId, projectId))
	}
	return creds
}

// TestJsonCredential creates a json credential in the
// provided DB with the provided scope and any values passed in. If any
// errors are encountered during the creation of the store, the test will fail.
func TestJsonCredential(
	t testing.TB,
	conn *db.DB,
	wrapper wrapping.Wrapper,
	storeId, scopeId string,
	object credential.JsonObject,
	opt ...Option,
) *JsonCredential {
	t.Helper()
	ctx := context.Background()
	kmsCache := kms.TestKms(t, conn, wrapper)
	w := db.New(conn)

	opts := getOpts(opt...)

	databaseWrapper, err := kmsCache.GetWrapper(ctx, scopeId, kms.KeyPurposeDatabase)
	assert.NoError(t, err)
	require.NotNil(t, databaseWrapper)

	cred, err := NewJsonCredential(ctx, storeId, object, opt...)
	require.NoError(t, err)
	require.NotNil(t, cred)

	id := opts.withPublicId
	if id == "" {
		id, err = credential.NewJsonCredentialId(ctx)
		require.NoError(t, err)
	}
	cred.PublicId = id

	err = cred.encrypt(ctx, databaseWrapper)
	require.NoError(t, err)

	_, err2 := w.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(_ db.Reader, iw db.Writer) error {
			require.NoError(t, iw.Create(ctx, cred))
			return nil
		},
	)
	require.NoError(t, err2)

	return cred
}

// TestJsonCredentials creates count number of json
// credentials in the provided DB with the provided scope id. If any errors are
// encountered during the creation of the credentials, the test will fail.
func TestJsonCredentials(
	t testing.TB,
	conn *db.DB,
	wrapper wrapping.Wrapper,
	storeId, scopeId string,
	object credential.JsonObject,
	count int,
) []*JsonCredential {
	t.Helper()
	ctx := context.Background()
	kmsCache := kms.TestKms(t, conn, wrapper)

	databaseWrapper, err := kmsCache.GetWrapper(ctx, scopeId, kms.KeyPurposeDatabase)
	assert.NoError(t, err)
	require.NotNil(t, databaseWrapper)

	creds := make([]*JsonCredential, 0, count)
	for i := 0; i < count; i++ {
		creds = append(creds, TestJsonCredential(t, conn, wrapper, storeId, scopeId, object))
	}
	return creds
}
