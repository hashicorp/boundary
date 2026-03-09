// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/credential/vault/store"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/scheduler"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestCreateLdapCredentialLibrary(t *testing.T) {
	t.Parallel()

	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)

	_, proj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	cs := TestCredentialStores(t, conn, wrapper, proj.GetPublicId(), 1)[0]

	tests := []struct {
		name        string
		inProjectId string
		inDomainObj *LdapCredentialLibrary
		expOut      *LdapCredentialLibrary
		expErr      bool
		expErrMsg   string
	}{
		{
			name:        "noProjectId",
			inProjectId: "",
			inDomainObj: nil,
			expErr:      true,
			expErrMsg:   "no project id",
		},
		{
			name:        "nilDomainObject",
			inProjectId: proj.GetPublicId(),
			inDomainObj: nil,
			expErr:      true,
			expErrMsg:   "nil input domain object",
		},
		{
			name:        "nilStoreObject",
			inProjectId: proj.GetPublicId(),
			inDomainObj: &LdapCredentialLibrary{LdapCredentialLibrary: nil},
			expErr:      true,
			expErrMsg:   "nil input domain object",
		},
		{
			name:        "emptyObject",
			inProjectId: proj.GetPublicId(),
			inDomainObj: &LdapCredentialLibrary{LdapCredentialLibrary: &store.LdapCredentialLibrary{}},
			expErr:      true,
			expErrMsg:   "no store id",
		},
		{
			name:        "withPublicId",
			inProjectId: proj.GetPublicId(),
			inDomainObj: &LdapCredentialLibrary{
				LdapCredentialLibrary: &store.LdapCredentialLibrary{
					PublicId:    "cvllt_3o2iuhOpZ",
					StoreId:     cs.GetPublicId(),
					Name:        "withPublicId",
					Description: "withPublicId Subtest",
					VaultPath:   "ldap/creds/dynamic1",
				},
			},
			expErr:    true,
			expErrMsg: "public id not empty",
		},
		{
			name:        "noStoreId",
			inProjectId: proj.GetPublicId(),
			inDomainObj: &LdapCredentialLibrary{
				LdapCredentialLibrary: &store.LdapCredentialLibrary{
					StoreId:     "",
					Name:        "noStoreId",
					Description: "noStoreId Subtest",
					VaultPath:   "ldap/creds/dynamic1",
				},
			},
			expErr:    true,
			expErrMsg: "no store id",
		},
		{
			name:        "noVaultPath",
			inProjectId: proj.GetPublicId(),
			inDomainObj: &LdapCredentialLibrary{
				LdapCredentialLibrary: &store.LdapCredentialLibrary{
					StoreId:     cs.GetPublicId(),
					Name:        "noVaultPath",
					Description: "noVaultPath Subtest",
					VaultPath:   "",
				},
			},
			expErr:    true,
			expErrMsg: "no vault path",
		},
		{
			name:        "invalidCredentialType",
			inProjectId: proj.GetPublicId(),
			inDomainObj: &LdapCredentialLibrary{
				LdapCredentialLibrary: &store.LdapCredentialLibrary{
					StoreId:        cs.GetPublicId(),
					Name:           "invalidCredentialType",
					Description:    "invalidCredentialType Subtest",
					VaultPath:      "ldap/creds/dynamic1",
					CredentialType: "cred_type_that_doesnt_exist",
				},
			},
			expErr:    true,
			expErrMsg: "invalid credential type",
		},
		{
			name:        "invalidVaultPath1",
			inProjectId: proj.GetPublicId(),
			inDomainObj: &LdapCredentialLibrary{
				LdapCredentialLibrary: &store.LdapCredentialLibrary{
					StoreId:     cs.GetPublicId(),
					Name:        "invalidVaultPath1",
					Description: "invalidVaultPath1 Subtest",
					VaultPath:   "ldap/bad/some/test/path",
				},
			},
			expErr:    true,
			expErrMsg: "vault_path_must_have_staticcred_or_creds constraint failed",
		},
		{
			name:        "invalidVaultPath2",
			inProjectId: proj.GetPublicId(),
			inDomainObj: &LdapCredentialLibrary{
				LdapCredentialLibrary: &store.LdapCredentialLibrary{
					StoreId:     cs.GetPublicId(),
					Name:        "invalidVaultPath2",
					Description: "invalidVaultPath2 Subtest",
					VaultPath:   "ldap/static-credbad/some/test/path",
				},
			},
			expErr:    true,
			expErrMsg: "vault_path_must_have_staticcred_or_creds constraint failed",
		},
		{
			name:        "invalidVaultPath3",
			inProjectId: proj.GetPublicId(),
			inDomainObj: &LdapCredentialLibrary{
				LdapCredentialLibrary: &store.LdapCredentialLibrary{
					StoreId:     cs.GetPublicId(),
					Name:        "invalidVaultPath3",
					Description: "invalidVaultPath3 Subtest",
					VaultPath:   "ldap/badstatic-cred/some/test/path",
				},
			},
			expErr:    true,
			expErrMsg: "vault_path_must_have_staticcred_or_creds constraint failed",
		},
		{
			name:        "invalidVaultPath4",
			inProjectId: proj.GetPublicId(),
			inDomainObj: &LdapCredentialLibrary{
				LdapCredentialLibrary: &store.LdapCredentialLibrary{
					StoreId:     cs.GetPublicId(),
					Name:        "invalidVaultPath4",
					Description: "invalidVaultPath4 Subtest",
					VaultPath:   "ldap/credsbad/some/test/path",
				},
			},
			expErr:    true,
			expErrMsg: "vault_path_must_have_staticcred_or_creds constraint failed",
		},
		{
			name:        "invalidVaultPath5",
			inProjectId: proj.GetPublicId(),
			inDomainObj: &LdapCredentialLibrary{
				LdapCredentialLibrary: &store.LdapCredentialLibrary{
					StoreId:     cs.GetPublicId(),
					Name:        "invalidVaultPath5",
					Description: "invalidVaultPath5 Subtest",
					VaultPath:   "ldap/badcreds/some/test/path",
				},
			},
			expErr:    true,
			expErrMsg: "vault_path_must_have_staticcred_or_creds constraint failed",
		},
		{
			name:        "validStaticCred1",
			inProjectId: proj.GetPublicId(),
			inDomainObj: &LdapCredentialLibrary{
				LdapCredentialLibrary: &store.LdapCredentialLibrary{
					StoreId:     cs.GetPublicId(),
					Name:        "validStaticCred1",
					Description: "validStaticCred1 Subtest",
					VaultPath:   "ldap/static-cred/some/test/path",
				},
			},
			expOut: &LdapCredentialLibrary{
				LdapCredentialLibrary: &store.LdapCredentialLibrary{
					Name:        "validStaticCred1",
					Description: "validStaticCred1 Subtest",
					VaultPath:   "ldap/static-cred/some/test/path",
				},
			},
		},
		{
			name:        "validStaticCred2",
			inProjectId: proj.GetPublicId(),
			inDomainObj: &LdapCredentialLibrary{
				LdapCredentialLibrary: &store.LdapCredentialLibrary{
					StoreId:     cs.GetPublicId(),
					Name:        "validStaticCred2",
					Description: "validStaticCred2 Subtest",
					VaultPath:   "/ldap/static-cred/path",
				},
			},
			expOut: &LdapCredentialLibrary{
				LdapCredentialLibrary: &store.LdapCredentialLibrary{
					Name:        "validStaticCred2",
					Description: "validStaticCred2 Subtest",
					VaultPath:   "/ldap/static-cred/path",
				},
			},
		},
		{
			name:        "validDynamicCreds1",
			inProjectId: proj.GetPublicId(),
			inDomainObj: &LdapCredentialLibrary{
				LdapCredentialLibrary: &store.LdapCredentialLibrary{
					StoreId:     cs.GetPublicId(),
					Name:        "validDynamicCreds1",
					Description: "validDynamicCreds1 Subtest",
					VaultPath:   "ldap/creds/some/test/path",
				},
			},
			expOut: &LdapCredentialLibrary{
				LdapCredentialLibrary: &store.LdapCredentialLibrary{
					Name:        "validDynamicCreds1",
					Description: "validDynamicCreds1 Subtest",
					VaultPath:   "ldap/creds/some/test/path",
				},
			},
		},
		{
			name:        "validDynamicCreds2",
			inProjectId: proj.GetPublicId(),
			inDomainObj: &LdapCredentialLibrary{
				LdapCredentialLibrary: &store.LdapCredentialLibrary{
					StoreId:     cs.GetPublicId(),
					Name:        "validDynamicCreds2",
					Description: "validDynamicCreds2 Subtest",
					VaultPath:   "/ldap/creds/path",
				},
			},
			expOut: &LdapCredentialLibrary{
				LdapCredentialLibrary: &store.LdapCredentialLibrary{
					Name:        "validDynamicCreds2",
					Description: "validDynamicCreds2 Subtest",
					VaultPath:   "/ldap/creds/path",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kms := kms.TestKms(t, conn, wrapper)
			sche := scheduler.TestScheduler(t, conn, wrapper)
			rw := db.New(conn)

			repo, err := NewRepository(t.Context(), rw, rw, kms, sche)
			require.NoError(t, err)
			require.NotNil(t, repo)

			ldapCredLib, err := repo.CreateLdapCredentialLibrary(t.Context(), tt.inProjectId, tt.inDomainObj)
			if tt.expErr {
				require.ErrorContains(t, err, tt.expErrMsg)
				require.Nil(t, ldapCredLib)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, ldapCredLib)

			require.Contains(t, ldapCredLib.GetPublicId(), globals.VaultLdapCredentialLibraryPrefix)
			require.NotEmpty(t, ldapCredLib.GetCreateTime())
			require.NotEmpty(t, ldapCredLib.GetUpdateTime())
			require.EqualValues(t, cs.GetPublicId(), ldapCredLib.GetStoreId())
			require.EqualValues(t, 1, ldapCredLib.GetVersion())
			require.EqualValues(t, string(globals.UsernamePasswordDomainCredentialType), ldapCredLib.GetCredentialType())
			require.EqualValues(t, tt.expOut.GetName(), ldapCredLib.GetName())
			require.EqualValues(t, tt.expOut.GetDescription(), ldapCredLib.GetDescription())
			require.EqualValues(t, tt.expOut.GetVaultPath(), ldapCredLib.GetVaultPath())
		})
	}
}

func TestUpdateLdapCredentialLibrary(t *testing.T) {
	t.Parallel()

	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)

	_, proj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	cs := TestCredentialStores(t, conn, wrapper, proj.GetPublicId(), 1)[0]

	kms := kms.TestKms(t, conn, wrapper)
	sche := scheduler.TestScheduler(t, conn, wrapper)
	rw := db.New(conn)

	repo, err := NewRepository(t.Context(), rw, rw, kms, sche)
	require.NoError(t, err)
	require.NotNil(t, repo)

	t.Run("nilDomainObject", func(t *testing.T) {
		l, updated, err := repo.UpdateLdapCredentialLibrary(t.Context(), proj.GetPublicId(), nil, 1, []string{})
		require.ErrorContains(t, err, "nil domain object")
		require.EqualValues(t, 0, updated)
		require.Nil(t, l)
	})

	t.Run("nilStoreObject", func(t *testing.T) {
		l, updated, err := repo.UpdateLdapCredentialLibrary(t.Context(), proj.GetPublicId(),
			&LdapCredentialLibrary{LdapCredentialLibrary: nil}, 1, []string{})
		require.ErrorContains(t, err, "nil domain object")
		require.EqualValues(t, 0, updated)
		require.Nil(t, l)
	})

	t.Run("emptyDomainObject", func(t *testing.T) {
		l, updated, err := repo.UpdateLdapCredentialLibrary(t.Context(), proj.GetPublicId(),
			&LdapCredentialLibrary{LdapCredentialLibrary: &store.LdapCredentialLibrary{}},
			1, []string{},
		)
		require.ErrorContains(t, err, "missing public id")
		require.EqualValues(t, 0, updated)
		require.Nil(t, l)
	})

	t.Run("credLibDoesntExist", func(t *testing.T) {
		l, updated, err := repo.UpdateLdapCredentialLibrary(t.Context(), proj.GetPublicId(),
			&LdapCredentialLibrary{
				LdapCredentialLibrary: &store.LdapCredentialLibrary{PublicId: "doesnt_exist"},
			}, 1, []string{"name", "description"},
		)
		require.ErrorContains(t, err, "record not found, search issue")
		require.EqualValues(t, 0, updated)
		require.Nil(t, l)
	})

	updateNameFn := func(name string) func(*LdapCredentialLibrary) *LdapCredentialLibrary {
		return func(lcl *LdapCredentialLibrary) *LdapCredentialLibrary {
			lcl.Name = name
			return lcl
		}
	}
	updateDescriptionFn := func(description string) func(*LdapCredentialLibrary) *LdapCredentialLibrary {
		return func(lcl *LdapCredentialLibrary) *LdapCredentialLibrary {
			lcl.Description = description
			return lcl
		}
	}
	updateVaultPathFn := func(vaultPath string) func(*LdapCredentialLibrary) *LdapCredentialLibrary {
		return func(lcl *LdapCredentialLibrary) *LdapCredentialLibrary {
			lcl.VaultPath = vaultPath
			return lcl
		}
	}
	updateStoreIdFn := func() func(*LdapCredentialLibrary) *LdapCredentialLibrary {
		return func(lcl *LdapCredentialLibrary) *LdapCredentialLibrary {
			lcl.StoreId = "this_is_immutable"
			return lcl
		}
	}

	tests := []struct {
		name        string
		inProjectId string
		inVersion   uint32
		inFieldMask []string
		changeFns   []func(*LdapCredentialLibrary) *LdapCredentialLibrary
		expUpdate   bool
		expOut      *LdapCredentialLibrary
		expErr      bool
		expErrStr   string
	}{
		{
			name:        "noProjectId",
			inProjectId: "",
			inVersion:   1,
			inFieldMask: []string{"somepath"},
			expErr:      true,
			expErrStr:   "no project id",
		},
		{
			name:        "noVersion",
			inProjectId: proj.GetPublicId(),
			inVersion:   0,
			inFieldMask: []string{"somepath"},
			expErr:      true,
			expErrStr:   "missing version",
		},
		{
			name:        "missingFieldMask",
			inProjectId: proj.GetPublicId(),
			inVersion:   1,
			inFieldMask: []string{},
			expErr:      true,
			expErrStr:   "missing field mask",
		},
		{
			name:        "unsupportedFieldInFieldMask",
			inProjectId: proj.GetPublicId(),
			inVersion:   1,
			inFieldMask: []string{"name", "storeId"},
			expErr:      true,
			expErrStr:   `"storeId" field mask path is unsupported`,
		},
		{
			name:        "updateToInvalidVaultPath1",
			inProjectId: proj.GetPublicId(),
			inVersion:   1,
			inFieldMask: []string{"vaultPath"},
			changeFns: []func(*LdapCredentialLibrary) *LdapCredentialLibrary{
				updateVaultPathFn("ldap/credbad/new"),
			},
			expErr:    true,
			expErrStr: "vault_path_must_have_staticcred_or_creds constraint failed",
		},
		{
			name:        "updateToInvalidVaultPath2",
			inProjectId: proj.GetPublicId(),
			inVersion:   1,
			inFieldMask: []string{"vaultPath"},
			changeFns: []func(*LdapCredentialLibrary) *LdapCredentialLibrary{
				updateVaultPathFn("ldap/static-credbad/new"),
			},
			expErr:    true,
			expErrStr: "vault_path_must_have_staticcred_or_creds constraint failed",
		},
		{
			name:        "updateAndFieldMaskMismatch",
			inProjectId: proj.GetPublicId(),
			inVersion:   1,
			inFieldMask: []string{"name"},
			changeFns: []func(*LdapCredentialLibrary) *LdapCredentialLibrary{
				updateDescriptionFn("updateAndFieldMaskMismatch Updated Description"),
			},
			expUpdate: false,
			expOut: &LdapCredentialLibrary{
				LdapCredentialLibrary: &store.LdapCredentialLibrary{
					Name:        "TestUpdateLdapCredentialLibrary/updateAndFieldMaskMismatch Original Name",
					Description: "TestUpdateLdapCredentialLibrary/updateAndFieldMaskMismatch Original Description",
					VaultPath:   "ldap/creds/path",
				},
			},
		},
		{
			name:        "validUpdateName",
			inProjectId: proj.GetPublicId(),
			inVersion:   1,
			inFieldMask: []string{"name"},
			changeFns: []func(*LdapCredentialLibrary) *LdapCredentialLibrary{
				updateNameFn("validUpdateName Subtest Updated Name"),
			},
			expUpdate: true,
			expOut: &LdapCredentialLibrary{
				LdapCredentialLibrary: &store.LdapCredentialLibrary{
					Name:        "validUpdateName Subtest Updated Name",
					Description: "TestUpdateLdapCredentialLibrary/validUpdateName Original Description",
					VaultPath:   "ldap/creds/path",
				},
			},
		},
		{
			name:        "validUpdateDescription",
			inProjectId: proj.GetPublicId(),
			inVersion:   1,
			inFieldMask: []string{"description"},
			changeFns: []func(*LdapCredentialLibrary) *LdapCredentialLibrary{
				updateDescriptionFn("validUpdateDescription Subtest Updated Description"),
			},
			expUpdate: true,
			expOut: &LdapCredentialLibrary{
				LdapCredentialLibrary: &store.LdapCredentialLibrary{
					Name:        "TestUpdateLdapCredentialLibrary/validUpdateDescription Original Name",
					Description: "validUpdateDescription Subtest Updated Description",
					VaultPath:   "ldap/creds/path",
				},
			},
		},
		{
			name:        "validUpdateVaultPath",
			inProjectId: proj.GetPublicId(),
			inVersion:   1,
			inFieldMask: []string{"vaultPath"},
			changeFns: []func(*LdapCredentialLibrary) *LdapCredentialLibrary{
				updateVaultPathFn("ldap/creds/updated/path/new"),
			},
			expUpdate: true,
			expOut: &LdapCredentialLibrary{
				LdapCredentialLibrary: &store.LdapCredentialLibrary{
					Name:        "TestUpdateLdapCredentialLibrary/validUpdateVaultPath Original Name",
					Description: "TestUpdateLdapCredentialLibrary/validUpdateVaultPath Original Description",
					VaultPath:   "ldap/creds/updated/path/new",
				},
			},
		},
		{
			name:        "validUpdateMultipleFields",
			inProjectId: proj.GetPublicId(),
			inVersion:   1,
			inFieldMask: []string{"name", "description", "vaultPath"},
			changeFns: []func(*LdapCredentialLibrary) *LdapCredentialLibrary{
				updateNameFn("validUpdateMultipleFields Updated Name"),
				updateDescriptionFn("validUpdateMultipleFields Updated Description"),
				updateVaultPathFn("ldap/static-cred/updated/path/new"),
			},
			expUpdate: true,
			expOut: &LdapCredentialLibrary{
				LdapCredentialLibrary: &store.LdapCredentialLibrary{
					Name:        "validUpdateMultipleFields Updated Name",
					Description: "validUpdateMultipleFields Updated Description",
					VaultPath:   "ldap/static-cred/updated/path/new",
				},
			},
		},
		{
			name:        "validUpdateNameExtraChangesNotInFieldMask",
			inProjectId: proj.GetPublicId(),
			inVersion:   1,
			inFieldMask: []string{"name"},
			changeFns: []func(*LdapCredentialLibrary) *LdapCredentialLibrary{
				updateNameFn("validUpdateNameExtraChanges Updated Name"),
				updateDescriptionFn("validUpdateNameExtraChanges Updated Description"),
				updateVaultPathFn("ldap/creds/updated/path/new"),
				updateStoreIdFn(),
			},
			expUpdate: true,
			expOut: &LdapCredentialLibrary{
				LdapCredentialLibrary: &store.LdapCredentialLibrary{
					Name:        "validUpdateNameExtraChanges Updated Name",
					Description: "TestUpdateLdapCredentialLibrary/validUpdateNameExtraChangesNotInFieldMask Original Description",
					VaultPath:   "ldap/creds/path",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			createdLib, err := repo.CreateLdapCredentialLibrary(t.Context(), proj.GetPublicId(), &LdapCredentialLibrary{
				LdapCredentialLibrary: &store.LdapCredentialLibrary{
					StoreId:     cs.GetPublicId(),
					Name:        t.Name() + " Original Name",
					Description: t.Name() + " Original Description",
					VaultPath:   "ldap/creds/path",
				},
			})
			require.NoError(t, err)
			require.NotNil(t, createdLib)

			inDomainObj := createdLib.clone()
			for _, changeFn := range tt.changeFns {
				inDomainObj = changeFn(inDomainObj)
			}

			updatedLdapLib, updated, err := repo.UpdateLdapCredentialLibrary(t.Context(),
				tt.inProjectId, inDomainObj, tt.inVersion, tt.inFieldMask,
			)
			if tt.expErr {
				require.ErrorContains(t, err, tt.expErrStr)
				require.Nil(t, updatedLdapLib)
				require.EqualValues(t, 0, updated)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, updatedLdapLib)
			require.NotNil(t, updatedLdapLib.LdapCredentialLibrary)

			if tt.expUpdate {
				require.Greater(t, updatedLdapLib.GetUpdateTime().AsTime(), createdLib.GetUpdateTime().AsTime())
				require.EqualValues(t, createdLib.GetVersion()+1, updatedLdapLib.GetVersion())
			} else {
				require.EqualValues(t, createdLib.GetUpdateTime().AsTime(), updatedLdapLib.GetUpdateTime().AsTime())
				require.EqualValues(t, createdLib.GetVersion(), updatedLdapLib.GetVersion())
			}
			require.EqualValues(t, 1, updated)
			require.EqualValues(t, createdLib.GetPublicId(), updatedLdapLib.GetPublicId())
			require.EqualValues(t, createdLib.GetCreateTime().AsTime(), updatedLdapLib.GetCreateTime().AsTime())
			require.EqualValues(t, createdLib.GetStoreId(), updatedLdapLib.GetStoreId())
			require.EqualValues(t, createdLib.GetCredentialType(), updatedLdapLib.GetCredentialType())
			require.EqualValues(t, tt.expOut.GetName(), updatedLdapLib.GetName())
			require.EqualValues(t, tt.expOut.GetDescription(), updatedLdapLib.GetDescription())
			require.EqualValues(t, tt.expOut.GetVaultPath(), updatedLdapLib.GetVaultPath())
		})
	}
}

func TestLookupLdapCredentialLibrary(t *testing.T) {
	t.Parallel()

	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)

	_, proj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	cs := TestCredentialStores(t, conn, wrapper, proj.GetPublicId(), 1)[0]

	kms := kms.TestKms(t, conn, wrapper)
	sche := scheduler.TestScheduler(t, conn, wrapper)
	rw := db.New(conn)

	repo, err := NewRepository(t.Context(), rw, rw, kms, sche)
	require.NoError(t, err)
	require.NotNil(t, repo)

	t.Run("noPublicId", func(t *testing.T) {
		l, err := repo.LookupLdapCredentialLibrary(t.Context(), "")
		require.ErrorContains(t, err, "no public id")
		require.Nil(t, l)
	})

	t.Run("credLibNotFound", func(t *testing.T) {
		l, err := repo.LookupLdapCredentialLibrary(t.Context(), "alibthat_doesnt_exist")
		require.NoError(t, err)
		require.Nil(t, l)
	})

	t.Run("success", func(t *testing.T) {
		createdLib, err := repo.CreateLdapCredentialLibrary(t.Context(), proj.GetPublicId(), &LdapCredentialLibrary{
			LdapCredentialLibrary: &store.LdapCredentialLibrary{
				StoreId:     cs.GetPublicId(),
				Name:        "success",
				Description: "success Subtest",
				VaultPath:   "ldap/creds/path",
			},
		})
		require.NoError(t, err)
		require.NotNil(t, createdLib)

		lookupLib, err := repo.LookupLdapCredentialLibrary(t.Context(), createdLib.GetPublicId())
		require.NoError(t, err)
		require.Empty(t, cmp.Diff(createdLib, lookupLib, protocmp.Transform()))
	})
}

func TestDeleteLdapCredentialLibrary(t *testing.T) {
	t.Parallel()

	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)

	_, proj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	cs := TestCredentialStores(t, conn, wrapper, proj.GetPublicId(), 1)[0]

	kms := kms.TestKms(t, conn, wrapper)
	sche := scheduler.TestScheduler(t, conn, wrapper)
	rw := db.New(conn)

	repo, err := NewRepository(t.Context(), rw, rw, kms, sche)
	require.NoError(t, err)
	require.NotNil(t, repo)

	t.Run("noPublicId", func(t *testing.T) {
		deleted, err := repo.DeleteLdapCredentialLibrary(t.Context(), proj.GetPublicId(), "")
		require.ErrorContains(t, err, "no public id")
		require.EqualValues(t, 0, deleted)
	})

	t.Run("noProjectId", func(t *testing.T) {
		deleted, err := repo.DeleteLdapCredentialLibrary(t.Context(), "", "cvllt_doesntexist")
		require.ErrorContains(t, err, "no project id")
		require.EqualValues(t, 0, deleted)
	})

	t.Run("credLibDoesntExist", func(t *testing.T) {
		deleted, err := repo.DeleteLdapCredentialLibrary(t.Context(), proj.GetPublicId(), "cvllt_doesntexist")
		require.NoError(t, err)
		require.EqualValues(t, 0, deleted)
	})

	t.Run("success", func(t *testing.T) {
		createdLib, err := repo.CreateLdapCredentialLibrary(t.Context(), proj.GetPublicId(), &LdapCredentialLibrary{
			LdapCredentialLibrary: &store.LdapCredentialLibrary{
				StoreId:     cs.GetPublicId(),
				Name:        "success",
				Description: "success Subtest",
				VaultPath:   "ldap/creds/path",
			},
		})
		require.NoError(t, err)
		require.NotNil(t, createdLib)

		lookupLib, err := repo.LookupLdapCredentialLibrary(t.Context(), createdLib.GetPublicId())
		require.NoError(t, err)
		require.Empty(t, cmp.Diff(createdLib, lookupLib, protocmp.Transform()))

		deleted, err := repo.DeleteLdapCredentialLibrary(t.Context(), proj.GetPublicId(), lookupLib.GetPublicId())
		require.NoError(t, err)
		require.EqualValues(t, 1, deleted)

		lookupLib2, err := repo.LookupLdapCredentialLibrary(t.Context(), createdLib.GetPublicId())
		require.NoError(t, err)
		require.Nil(t, lookupLib2)
	})
}
