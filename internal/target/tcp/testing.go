// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package tcp

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/go-uuid"
	"github.com/stretchr/testify/require"
)

// TestTarget is used to create a Target that can be used by tests in other packages.
func TestTarget(ctx context.Context, t testing.TB, conn *db.DB, projectId, name string, opt ...target.Option) target.Target {
	t.Helper()
	opt = append(opt, target.WithName(name))
	opts := target.GetOpts(opt...)
	require := require.New(t)
	rw := db.New(conn)
	tar, err := target.New(ctx, Subtype, projectId, opt...)
	require.NoError(err)
	id, err := db.NewPublicId(ctx, TargetPrefix)
	require.NoError(err)
	require.NoError(tar.SetPublicId(ctx, id))
	require.NoError(rw.Create(ctx, tar))

	if opts.WithAddress != "" {
		address, err := target.NewAddress(ctx, tar.GetPublicId(), opts.WithAddress)
		require.NoError(err)
		require.NotNil(address)
		err = rw.Create(context.Background(), address)
		require.NoError(err)
	}
	if len(opts.WithHostSources) > 0 {
		newHostSets := make([]*target.TargetHostSet, 0, len(opts.WithHostSources))
		for _, s := range opts.WithHostSources {
			hostSet, err := target.NewTargetHostSet(ctx, tar.GetPublicId(), s)
			require.NoError(err)
			newHostSets = append(newHostSets, hostSet)
		}
		err := rw.CreateItems(ctx, newHostSets)
		require.NoError(err)
	}
	if len(opts.WithCredentialLibraries) > 0 {
		newCredLibs := make([]*target.CredentialLibrary, 0, len(opts.WithCredentialLibraries))
		for _, cl := range opts.WithCredentialLibraries {
			cl.TargetId = tar.GetPublicId()
			newCredLibs = append(newCredLibs, cl)
		}
		err := rw.CreateItems(ctx, newCredLibs)
		require.NoError(err)
	}
	if len(opts.WithStaticCredentials) > 0 {
		newCreds := make([]*target.StaticCredential, 0, len(opts.WithStaticCredentials))
		for _, c := range opts.WithStaticCredentials {
			c.TargetId = tar.GetPublicId()
			newCreds = append(newCreds, c)
		}
		err := rw.CreateItems(ctx, newCreds)
		require.NoError(err)
	}
	return tar
}

func testTargetName(t testing.TB, projectId string) string {
	t.Helper()
	return fmt.Sprintf("%s-%s", projectId, testId(t))
}

func testId(t testing.TB) string {
	t.Helper()
	id, err := uuid.GenerateUUID()
	require.NoError(t, err)
	return fmt.Sprintf("%s_%s", TargetPrefix, id)
}
