// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package tcp_test

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/credential/vault"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/host/static"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/internal/target/tcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_TestTcpTarget(t *testing.T) {
	t.Parallel()

	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	ctx := context.Background()
	repo, err := target.NewRepository(ctx, rw, rw, testKms)
	require.NoError(t, err)

	t.Run("with-host-source", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		_, proj := iam.TestScopes(t, iamRepo)
		cats := static.TestCatalogs(t, conn, proj.PublicId, 1)
		hsets := static.TestSets(t, conn, cats[0].GetPublicId(), 2)
		var sets []string
		for _, s := range hsets {
			sets = append(sets, s.PublicId)
		}
		name := tcp.TestTargetName(t, proj.PublicId)
		tar := tcp.TestTarget(ctx, t, conn, proj.PublicId, name, target.WithHostSources(sets))
		require.NotNil(t)
		assert.NotEmpty(tar.GetPublicId())
		assert.Equal(name, tar.GetName())
		assert.Empty(tar.GetAddress())

		foundTarget, err := repo.LookupTarget(context.Background(), tar.GetPublicId())
		require.NoError(err)

		foundSources := foundTarget.GetHostSources()
		foundIds := make([]string, 0, len(foundSources))
		for _, s := range foundSources {
			foundIds = append(foundIds, s.Id())
		}
		assert.ElementsMatch(sets, foundIds)
	})

	tests := []struct {
		name        string
		opt         []target.Option
		wantAddress string
	}{
		{
			name: "dns-name",
			opt: []target.Option{
				target.WithAddress("www.google.com"),
			},
			wantAddress: "www.google.com",
		},
		{
			name: "ipv4-address",
			opt: []target.Option{
				target.WithAddress("8.8.8.8"),
			},
			wantAddress: "8.8.8.8",
		},
		{
			name: "ipv4-address-with-port",
			opt: []target.Option{
				target.WithAddress("8.8.8.8:80"),
			},
			wantAddress: "8.8.8.8:80",
		},
		{
			name: "ipv6-address",
			opt: []target.Option{
				target.WithAddress("2001:4860:4860:0:0:0:0:8888"),
			},
			wantAddress: "2001:4860:4860:0:0:0:0:8888",
		},
		{
			name: "ipv6-address-with-port",
			opt: []target.Option{
				target.WithAddress("[2001:4860:4860:0:0:0:0:8888]:80"),
			},
			wantAddress: "[2001:4860:4860:0:0:0:0:8888]:80",
		},
		{
			name: "abbreviated-ipv6-address",
			opt: []target.Option{
				target.WithAddress("2001:4860:4860::8888"),
			},
			wantAddress: "2001:4860:4860::8888",
		},
		{
			name: "abbreviated-ipv6-address-with-port",
			opt: []target.Option{
				target.WithAddress("[2001:4860:4860::8888]:80"),
			},
			wantAddress: "[2001:4860:4860::8888]:80",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			_, proj := iam.TestScopes(t, iamRepo)
			name := tcp.TestTargetName(t, proj.PublicId)
			tar := tcp.TestTarget(ctx, t, conn, proj.PublicId, name, tt.opt...)
			require.NotNil(t)
			assert.NotEmpty(tar.GetPublicId())
			assert.Equal(name, tar.GetName())
			if tt.wantAddress != "" {
				assert.Equal(tt.wantAddress, tar.GetAddress())
				assert.Empty(tar.GetHostSources())
			} else {
				assert.Empty(tar.GetAddress())
			}
		})
	}
}

func Test_TestCredentialLibrary(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	_, proj := iam.TestScopes(t, iamRepo)

	ctx := context.Background()
	repo, err := target.NewRepository(ctx, rw, rw, testKms)
	require.NoError(err)

	tar := tcp.TestTarget(ctx, t, conn, proj.PublicId, t.Name())
	store := vault.TestCredentialStores(t, conn, wrapper, proj.GetPublicId(), 1)[0]
	vlibs := vault.TestCredentialLibraries(t, conn, wrapper, store.GetPublicId(), globals.UnspecifiedCredentialType, 2)
	var libIds []string
	var libs []*target.CredentialLibrary
	for _, v := range vlibs {
		libIds = append(libIds, v.GetPublicId())
		lib := target.TestCredentialLibrary(t, conn, tar.GetPublicId(), v.GetPublicId(), v.GetCredentialType())
		require.NotNil(lib)
		libs = append(libs, lib)
	}

	assert.Len(libs, 2)

	foundTarget, err := repo.LookupTarget(context.Background(), tar.GetPublicId())
	foundSources := foundTarget.GetCredentialSources()

	require.NoError(err)
	foundIds := make([]string, 0, len(foundSources))
	for _, s := range foundSources {
		foundIds = append(foundIds, s.Id())
	}
	require.ElementsMatch(libIds, foundIds)
}
