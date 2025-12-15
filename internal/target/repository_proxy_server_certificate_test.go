// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package target_test

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/globals"
	talias "github.com/hashicorp/boundary/internal/alias/target"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/internal/target/targettest"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFetchTargetProxyServerCertificate(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	wrapper := db.TestWrapper(t)
	conn, _ := db.TestSetup(t, "postgres")
	kmsCache := kms.TestKms(t, conn, wrapper)
	_, proj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	rw := db.New(conn)
	databaseWrapper, err := kmsCache.GetWrapper(ctx, proj.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)

	tar := targettest.TestNewTestTarget(ctx, t, conn, proj.PublicId, "test-target")

	// Create our default localhost target cert
	cer, err := target.NewTargetProxyCertificate(ctx, target.WithTargetId(tar.GetPublicId()))
	require.NoError(t, err)
	require.NotNil(t, cer)
	id, err := db.NewPublicId(ctx, globals.ProxyServerCertificatePrefix)
	require.NoError(t, err)
	cer.PublicId = id
	err = cer.Encrypt(ctx, databaseWrapper)
	require.NoError(t, err)
	err = rw.Create(ctx, cer)
	require.NoError(t, err)

	tests := []struct {
		name            string
		reader          db.Reader
		writer          db.Writer
		targetId        string
		scopeId         string
		wrapper         wrapping.Wrapper
		sessionMaxSecs  uint32
		wantErr         bool
		wantErrContains string
	}{
		{
			name:           "successful-lookup",
			reader:         rw,
			writer:         rw,
			targetId:       tar.GetPublicId(),
			scopeId:        proj.PublicId,
			wrapper:        databaseWrapper,
			sessionMaxSecs: 28800,
		},
		{
			name:           "successful-max-secs-causes-cert-regen",
			reader:         rw,
			writer:         rw,
			targetId:       tar.GetPublicId(),
			scopeId:        proj.PublicId,
			wrapper:        databaseWrapper,
			sessionMaxSecs: 60 * 60 * 24 * 600, // well over a year
		},
		{
			name:            "missing-reader",
			writer:          rw,
			targetId:        tar.GetPublicId(),
			scopeId:         proj.PublicId,
			wrapper:         databaseWrapper,
			sessionMaxSecs:  28800,
			wantErr:         true,
			wantErrContains: "reader is nil",
		},
		{
			name:            "missing-writer",
			reader:          rw,
			targetId:        tar.GetPublicId(),
			scopeId:         proj.PublicId,
			wrapper:         databaseWrapper,
			sessionMaxSecs:  28800,
			wantErr:         true,
			wantErrContains: "writer is nil",
		},
		{
			name:            "missing-target-id",
			reader:          rw,
			writer:          rw,
			scopeId:         proj.PublicId,
			wrapper:         databaseWrapper,
			sessionMaxSecs:  28800,
			wantErr:         true,
			wantErrContains: "target id is empty",
		},
		{
			name:            "missing-scope-id",
			reader:          rw,
			writer:          rw,
			targetId:        tar.GetPublicId(),
			wrapper:         databaseWrapper,
			sessionMaxSecs:  28800,
			wantErr:         true,
			wantErrContains: "scope id is empty",
		},
		{
			name:            "missing-wrapper",
			reader:          rw,
			writer:          rw,
			targetId:        tar.GetPublicId(),
			scopeId:         proj.PublicId,
			sessionMaxSecs:  28800,
			wantErr:         true,
			wantErrContains: "wrapper is nil",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			got, err := target.FetchTargetProxyServerCertificate(ctx, tt.reader, tt.writer, tt.targetId, tt.scopeId, tt.wrapper, tt.sessionMaxSecs)
			if tt.wantErr {
				require.Error(err)
				require.Contains(err.Error(), tt.wantErrContains)
				return
			}
			require.NoError(err)
			assert.NotNil(got)
		})
	}
}

func TestFetchTargetAliasProxyServerCertificate(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	wrapper := db.TestWrapper(t)
	conn, _ := db.TestSetup(t, "postgres")
	kmsCache := kms.TestKms(t, conn, wrapper)
	_, proj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	rw := db.New(conn)
	databaseWrapper, err := kmsCache.GetWrapper(ctx, proj.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)

	tar := targettest.TestNewTestTarget(ctx, t, conn, proj.PublicId, "test-target")

	// Create our default localhost target cert
	cer, err := target.NewTargetProxyCertificate(ctx, target.WithTargetId(tar.GetPublicId()))
	require.NoError(t, err)
	require.NotNil(t, cer)
	id, err := db.NewPublicId(ctx, globals.ProxyServerCertificatePrefix)
	require.NoError(t, err)
	cer.PublicId = id
	err = cer.Encrypt(ctx, databaseWrapper)
	require.NoError(t, err)
	err = rw.Create(ctx, cer)
	require.NoError(t, err)

	// Create an alias
	aliasValue := "test-alias"
	alias := talias.TestAlias(t, rw, aliasValue, talias.WithDestinationId(tar.GetPublicId()))
	require.NoError(t, err)
	require.NotNil(t, alias)

	tests := []struct {
		name            string
		reader          db.Reader
		writer          db.Writer
		targetId        string
		scopeId         string
		alias           *talias.Alias
		wrapper         wrapping.Wrapper
		sessionMaxSecs  uint32
		wantErr         bool
		wantErrContains string
	}{
		{
			name:           "successful-lookup",
			reader:         rw,
			writer:         rw,
			targetId:       tar.GetPublicId(),
			scopeId:        proj.PublicId,
			alias:          alias,
			wrapper:        databaseWrapper,
			sessionMaxSecs: 28800,
		},
		{
			name:           "successful-max-secs-causes-cert-regen",
			reader:         rw,
			writer:         rw,
			targetId:       tar.GetPublicId(),
			scopeId:        proj.PublicId,
			alias:          alias,
			wrapper:        databaseWrapper,
			sessionMaxSecs: 60 * 60 * 24 * 600, // well over a year
		},
		{
			name:            "missing-reader",
			writer:          rw,
			targetId:        tar.GetPublicId(),
			scopeId:         proj.PublicId,
			alias:           alias,
			wrapper:         databaseWrapper,
			sessionMaxSecs:  28800,
			wantErr:         true,
			wantErrContains: "reader is nil",
		},
		{
			name:            "missing-writer",
			reader:          rw,
			targetId:        tar.GetPublicId(),
			scopeId:         proj.PublicId,
			alias:           alias,
			wrapper:         databaseWrapper,
			sessionMaxSecs:  28800,
			wantErr:         true,
			wantErrContains: "writer is nil",
		},
		{
			name:            "missing-target-id",
			reader:          rw,
			writer:          rw,
			scopeId:         proj.PublicId,
			alias:           alias,
			wrapper:         databaseWrapper,
			sessionMaxSecs:  28800,
			wantErr:         true,
			wantErrContains: "target id is empty",
		},
		{
			name:            "missing-scope-id",
			reader:          rw,
			writer:          rw,
			targetId:        tar.GetPublicId(),
			alias:           alias,
			wrapper:         databaseWrapper,
			sessionMaxSecs:  28800,
			wantErr:         true,
			wantErrContains: "scope id is empty",
		},
		{
			name:            "missing-wrapper",
			reader:          rw,
			writer:          rw,
			targetId:        tar.GetPublicId(),
			scopeId:         proj.PublicId,
			alias:           alias,
			sessionMaxSecs:  28800,
			wantErr:         true,
			wantErrContains: "wrapper is nil",
		},
		{
			name:            "missing-alias",
			reader:          rw,
			writer:          rw,
			targetId:        tar.GetPublicId(),
			scopeId:         proj.PublicId,
			wrapper:         databaseWrapper,
			sessionMaxSecs:  28800,
			wantErr:         true,
			wantErrContains: "alias is nil",
		},
		{
			name:            "no-existing-localhost-cert-for-target",
			reader:          rw,
			writer:          rw,
			targetId:        "fake-id",
			alias:           alias,
			scopeId:         proj.PublicId,
			wrapper:         databaseWrapper,
			sessionMaxSecs:  28800,
			wantErr:         true,
			wantErrContains: "target proxy server certificate not found",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			got, err := target.FetchTargetAliasProxyServerCertificate(ctx, tt.reader, tt.writer, tt.targetId, tt.scopeId, tt.alias, tt.wrapper, tt.sessionMaxSecs)
			if tt.wantErr {
				require.Error(err)
				require.Contains(err.Error(), tt.wantErrContains)
				return
			}
			require.NoError(err)
			assert.NotNil(got)
		})
	}
}

func Test_FetchCertsWithinLookupTargetForSessionAuthorization(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, conn, wrapper)
	_, proj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	repo, err := target.NewRepository(context.Background(), rw, rw, testKms)
	require.NoError(t, err)
	databaseWrapper, err := testKms.GetWrapper(ctx, proj.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)

	tar := targettest.TestNewTestTarget(ctx, t, conn, proj.PublicId, "test-target")
	tar2 := targettest.TestNewTestTarget(ctx, t, conn, proj.PublicId, "test-target2")

	// Create an alias
	aliasValue := "test-alias"
	alias := talias.TestAlias(t, rw, aliasValue, talias.WithDestinationId(tar.GetPublicId()))
	require.NoError(t, err)
	require.NotNil(t, alias)

	// Create our default localhost target cert
	cer, err := target.NewTargetProxyCertificate(ctx, target.WithTargetId(tar.GetPublicId()))
	require.NoError(t, err)
	require.NotNil(t, cer)
	id, err := db.NewPublicId(ctx, globals.ProxyServerCertificatePrefix)
	require.NoError(t, err)
	cer.PublicId = id
	err = cer.Encrypt(ctx, databaseWrapper)
	require.NoError(t, err)
	err = rw.Create(ctx, cer)
	require.NoError(t, err)

	tests := []struct {
		name     string
		publicId string
		opt      []target.Option
		wantCert bool
	}{
		{
			name:     "success-get-target-with-certificate",
			publicId: tar.GetPublicId(),
			wantCert: true,
		},
		{
			name:     "success-get-target-with-alias-certificate",
			publicId: tar.GetPublicId(),
			opt: []target.Option{
				target.WithAlias(alias),
			},
			wantCert: true,
		},
		{
			name:     "success-get-target-no-cert",
			publicId: tar2.GetPublicId(),
			wantCert: false,
		},
		{
			name:     "success-get-target-no-cert-with-alias",
			publicId: tar2.GetPublicId(),
			opt: []target.Option{
				target.WithAlias(alias),
			},
			wantCert: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := repo.LookupTargetForSessionAuthorization(ctx, tt.publicId, proj.PublicId, tt.opt...)
			require.NoError(err)
			assert.NotNil(got)
			if tt.wantCert {
				assert.NotNil(got.GetProxyServerCertificate())
			} else {
				assert.Nil(got.GetProxyServerCertificate())
			}
		})
	}
}
