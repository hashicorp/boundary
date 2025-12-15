// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package target

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/target/store"
	"github.com/stretchr/testify/require"
)

// TestNewCredentialLibrary creates a new in memory CredentialLibrary
// representing the relationship between targetId and credentialLibraryId with
// the given purpose.
func TestNewCredentialLibrary(targetId, credentialLibraryId string, purpose credential.Purpose, credType string) *CredentialLibrary {
	return &CredentialLibrary{
		CredentialLibrary: &store.CredentialLibrary{
			TargetId:            targetId,
			CredentialLibraryId: credentialLibraryId,
			CredentialPurpose:   string(purpose),
		},
		CredentialType: credType,
	}
}

// TestNewTargetAddress creates a new in memory TargetAddress
// representing the association between a Target and network address.
func TestNewTargetAddress(targetId, address string) *Address {
	return &Address{
		TargetAddress: &store.TargetAddress{
			TargetId: targetId,
			Address:  address,
		},
	}
}

// TestNewStaticCredential creates a new in memory StaticCredential
// representing the relationship between targetId and credentialId with
// the given purpose.
func TestNewStaticCredential(targetId, credentialId string, purpose credential.Purpose) *StaticCredential {
	return &StaticCredential{
		StaticCredential: &store.StaticCredential{
			TargetId:          targetId,
			CredentialId:      credentialId,
			CredentialPurpose: string(purpose),
		},
	}
}

// TestCredentialLibrary creates a CredentialLibrary for targetId and
// libraryId with the credential purpose of brokered.
func TestCredentialLibrary(t testing.TB, conn *db.DB, targetId, libraryId, credType string) *CredentialLibrary {
	t.Helper()
	require := require.New(t)
	rw := db.New(conn)
	lib := TestNewCredentialLibrary(targetId, libraryId, credential.BrokeredPurpose, credType)
	err := rw.Create(context.Background(), lib)
	require.NoError(err)
	return lib
}

// TestTargetAddress creates am association for targetId and
// a given address value.
func TestTargetAddress(t testing.TB, conn *db.DB, targetId, address string) *Address {
	t.Helper()
	require := require.New(t)
	rw := db.New(conn)
	staticAddress := TestNewTargetAddress(targetId, address)
	err := rw.Create(context.Background(), staticAddress)
	require.NoError(err)
	return staticAddress
}

// TestListTargets exposes the repo listTargets method for testing purposes.
func TestListTargets(t testing.TB, repo *Repository, ctx context.Context, opts ...Option) ([]Target, time.Time) {
	targets, ttime, err := repo.listTargets(ctx, opts...)
	require.NoError(t, err)
	return targets, ttime
}

// TestListTargetsRefresh exposes the repo listTargetsRefresh method for testing purposes.
func TestListTargetsRefresh(t testing.TB, repo *Repository, ctx context.Context, updateAfter time.Time, opts ...Option) ([]Target, time.Time) {
	targets, ttime, err := repo.listTargetsRefresh(ctx, updateAfter, opts...)
	require.NoError(t, err)
	return targets, ttime
}

// TestListDeletedIds exposes the repo listDeletedIds method for testing purposes.
func TestListDeletedIds(t testing.TB, repo *Repository, ctx context.Context, since time.Time) ([]string, time.Time) {
	ids, ttime, err := repo.listDeletedIds(ctx, since)
	require.NoError(t, err)
	return ids, ttime
}

// TestEstimatedCount exposes the repo estimatedCount method for testing purposes.
func TestEstimatedCount(t testing.TB, repo *Repository, ctx context.Context) int {
	n, err := repo.estimatedCount(ctx)
	require.NoError(t, err)
	return n
}
