// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1


package target

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/target/store"
	"github.com/stretchr/testify/require"
)

// TestNewCredentialLibrary creates a new in memory CredentialLibrary
// representing the relationship between targetId and credentialLibraryId with
// the given purpose.
func TestNewCredentialLibrary(targetId, credentialLibraryId string, purpose credential.Purpose) *CredentialLibrary {
	return &CredentialLibrary{
		CredentialLibrary: &store.CredentialLibrary{
			TargetId:            targetId,
			CredentialLibraryId: credentialLibraryId,
			CredentialPurpose:   string(purpose),
		},
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
func TestCredentialLibrary(t testing.TB, conn *db.DB, targetId, libraryId string) *CredentialLibrary {
	t.Helper()
	require := require.New(t)
	rw := db.New(conn)
	lib := TestNewCredentialLibrary(targetId, libraryId, credential.BrokeredPurpose)
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
