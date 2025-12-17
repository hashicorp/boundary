// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package migration

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/daemon/controller"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_ManagedGroupTable(t *testing.T) {
	t.Parallel()
	tc := controller.NewTestController(t, nil)
	defer tc.Shutdown()

	rw := db.New(tc.DbConn())

	managedGroupId := "a_bcdefghijk"
	defaultPasswordAuthMethodId := "ampw_1234567890"
	defaultOidcAuthMethodId := "amoidc_1234567890"

	insertTests := []struct {
		testName     string
		publicId     string
		authMethodId string
		wantErr      bool
	}{
		{
			testName:     "invalid auth method",
			publicId:     managedGroupId,
			authMethodId: "amoid_1234567890",
			wantErr:      true,
		},
		{
			testName:     "valid",
			publicId:     managedGroupId,
			authMethodId: defaultOidcAuthMethodId,
			wantErr:      false,
		},
	}
	for _, tt := range insertTests {
		t.Run("insert: "+tt.testName, func(t *testing.T) {
			require := require.New(t)

			_, err := rw.Exec(context.Background(), "insert into auth_managed_group values (@public_id, @auth_method_id)",
				[]any{
					sql.Named("public_id", tt.publicId),
					sql.Named("auth_method_id", tt.authMethodId),
				})
			require.True(tt.wantErr == (err != nil))
		})
	}

	updateTests := []struct {
		testName string
		column   string
		value    string
		publicId string
		wantErr  bool
	}{
		{
			testName: "immutable public id",
			column:   "public_id",
			value:    "z_yxwvutsrqp",
			publicId: managedGroupId,
			wantErr:  true,
		},
		{
			testName: "immutable auth method",
			column:   "auth_method_id",
			value:    defaultPasswordAuthMethodId,
			publicId: managedGroupId,
			wantErr:  true,
		},
	}
	for _, tt := range updateTests {
		t.Run("update: "+tt.testName, func(t *testing.T) {
			assert := assert.New(t)
			_, err := rw.Exec(context.Background(), fmt.Sprintf("update auth_managed_group set %s = @value where public_id = @public_id", tt.column),
				[]any{
					sql.Named("value", tt.value),
					sql.Named("public_id", tt.publicId),
				})
			assert.True(tt.wantErr == (err != nil))
		})
	}
}

func Test_OidcManagedGroupTable(t *testing.T) {
	t.Parallel()
	tc := controller.NewTestController(t, nil)
	defer tc.Shutdown()

	ctx := context.Background()
	rw := db.New(tc.DbConn())

	managedGroupId := "a_bcdefghijk"
	defaultPasswordAuthMethodId := "ampw_1234567890"
	defaultOidcAuthMethodId := "amoidc_1234567890"
	name := "this is the name"
	filter := "this is a filter"

	// The first set of tests is for initial insertion
	{
		insertTests := []struct {
			testName     string
			publicId     string
			authMethodId string
			name         string
			filter       string
			wantErr      bool
		}{
			{
				testName:     "null filter",
				publicId:     managedGroupId,
				authMethodId: "amoid_1234567890",
				name:         name,
				filter:       "",
				wantErr:      true,
			},
			{
				testName:     "invalid auth method",
				publicId:     managedGroupId,
				authMethodId: defaultPasswordAuthMethodId,
				name:         name,
				filter:       filter,
				wantErr:      true,
			},
			{
				testName:     "valid",
				publicId:     managedGroupId,
				authMethodId: defaultOidcAuthMethodId,
				name:         name,
				filter:       filter,
				wantErr:      false,
			},
			{
				testName:     "duplicate public id",
				publicId:     managedGroupId,
				authMethodId: defaultOidcAuthMethodId,
				name:         name,
				filter:       filter,
				wantErr:      true,
			},
			{
				testName:     "duplicate name",
				publicId:     "z_yxwvutsrqp",
				authMethodId: defaultOidcAuthMethodId,
				name:         name,
				filter:       filter,
				wantErr:      true,
			},
		}
		for _, tt := range insertTests {
			t.Run("insert: "+tt.testName, func(t *testing.T) {
				require := require.New(t)
				_, err := rw.Exec(ctx, "insert into auth_oidc_managed_group (public_id, auth_method_id, name, filter) values (@public_id, @auth_method_id, @name, @filter)",
					[]any{
						sql.Named("public_id", tt.publicId),
						sql.Named("auth_method_id", tt.authMethodId),
						sql.Named("name", tt.name),
						sql.Named("filter", tt.filter),
					})
				require.True(tt.wantErr == (err != nil))
			})
		}
	}

	// Read some values to validate that things were set automatically
	rows, err := rw.Query(ctx, "select create_time, update_time, version from auth_oidc_managed_group", nil)
	require.NoError(t, err)
	require.True(t, rows.Next())
	var create_time, update_time time.Time
	var version int
	require.NoError(t, rows.Scan(&create_time, &update_time, &version))
	assert.False(t, create_time.IsZero())
	assert.Equal(t, update_time, create_time)
	assert.Equal(t, 1, version)

	// These update tests check immutability
	{
		updateTests := []struct {
			testName string
			column   string
			value    any
			wantErr  bool
		}{
			{
				testName: "immutable public id",
				column:   "public_id",
				value:    "z_yxwvutsrqp",
				wantErr:  true,
			},
			{
				testName: "immutable auth method",
				column:   "auth_method_id",
				value:    defaultPasswordAuthMethodId,
				wantErr:  true,
			},
			{
				testName: "immutable creation time",
				column:   "create_time",
				value:    time.Now(),
				wantErr:  true,
			},
			{
				testName: "valid",
				column:   "description",
				value:    "this is the description",
				wantErr:  false,
			},
		}
		for _, tt := range updateTests {
			t.Run("update: "+tt.testName, func(t *testing.T) {
				require := require.New(t)
				_, err = rw.Exec(ctx, fmt.Sprintf("update auth_oidc_managed_group set %s = @value where public_id = @public_id", tt.column),
					[]any{
						sql.Named("value", tt.value), sql.Named("public_id", managedGroupId),
					})
				require.True(tt.wantErr == (err != nil))
			})
		}
	}

	// Read values again to validate that things were updated automatically
	rows, err = rw.Query(ctx, "select create_time, update_time, version from auth_oidc_managed_group", nil)
	require.NoError(t, err)
	require.True(t, rows.Next())
	var updated_create_time, updated_update_time time.Time
	require.NoError(t, rows.Scan(&updated_create_time, &updated_update_time, &version))
	assert.Equal(t, create_time, updated_create_time)
	assert.NotEqual(t, update_time, updated_update_time)
	assert.Equal(t, 2, version)

	// Read values from auth_managed_group to ensure it was populated automatically
	rows, err = rw.Query(ctx, "select public_id, auth_method_id from auth_managed_group", nil)
	require.NoError(t, err)
	require.True(t, rows.Next())
	var public_id, auth_method_id string
	require.NoError(t, rows.Scan(&public_id, &auth_method_id))
	assert.Equal(t, managedGroupId, public_id)
	assert.Equal(t, defaultOidcAuthMethodId, auth_method_id)

	// Delete the value from the subtype table
	affected, err := rw.Exec(ctx, "delete from auth_oidc_managed_group where public_id = @public_id", []any{sql.Named("public_id", managedGroupId)})
	require.EqualValues(t, 1, affected)

	// It should no longer be in the base table
	rows, err = rw.Query(ctx, "select public_id, auth_method_id from auth_managed_group", nil)
	require.NoError(t, err)
	require.False(t, rows.Next())
}

func Test_AuthManagedOidcGroupMemberAccountTable(t *testing.T) {
	t.Parallel()
	tc := controller.NewTestController(t, nil)
	defer tc.Shutdown()

	ctx := context.Background()
	rw := db.New(tc.DbConn())

	managedGroupId := "a_bcdefghijk"
	defaultOidcAuthMethodId := "amoidc_1234567890"
	name := "this is the name"
	filter := "this is a filter"

	// Insert valid data in auth_oidc_managed_group to use for the following tests
	_, err := rw.Exec(ctx, "insert into auth_oidc_managed_group (public_id, auth_method_id, name, filter) values (@public_id, @auth_method_id, @name, @filter)",
		[]any{
			sql.Named("public_id", managedGroupId),
			sql.Named("auth_method_id", defaultOidcAuthMethodId),
			sql.Named("name", name),
			sql.Named("filter", filter),
		})
	require.NoError(t, err)

	// Fetch a valid (oidc) account ID to use in insertion
	rows, err := rw.Query(ctx, "select public_id from auth_oidc_account limit 1", nil)
	require.NoError(t, err)
	require.True(t, rows.Next())
	var accountId string
	require.NoError(t, rows.Scan(&accountId))
	require.NotEmpty(t, accountId)

	// The first set of tests is for initial insertion
	{
		insertTests := []struct {
			testName       string
			managedGroupId string
			memberId       string
			wantErr        bool
		}{
			{
				testName:       "invalid managed group id",
				managedGroupId: "z_yxwvutsrqp",
				memberId:       accountId,
				wantErr:        true,
			},
			{
				testName:       "invalid member id",
				managedGroupId: managedGroupId,
				memberId:       "acct_1234567890",
				wantErr:        true,
			},
			{
				testName:       "valid",
				managedGroupId: managedGroupId,
				memberId:       accountId,
				wantErr:        false,
			},
			{
				testName:       "duplicate values",
				managedGroupId: managedGroupId,
				memberId:       accountId,
				wantErr:        true,
			},
		}
		for _, tt := range insertTests {
			t.Run("insert: "+tt.testName, func(t *testing.T) {
				assert := assert.New(t)
				_, err = rw.Exec(ctx, "insert into auth_oidc_managed_group_member_account (managed_group_id, member_id) values (@group_id, @member_id)",
					[]any{
						sql.Named("group_id", tt.managedGroupId),
						sql.Named("member_id", tt.memberId),
					})
				assert.True(tt.wantErr == (err != nil))
			})
		}
	}

	// Read some values to validate that things were set automatically
	rows, err = rw.Query(ctx, "select create_time, managed_group_id, member_id from auth_oidc_managed_group_member_account", nil)
	require.NoError(t, err)
	require.True(t, rows.Next())
	var create_time time.Time
	var managed_group_id, member_id string
	require.NoError(t, rows.Scan(&create_time, &managed_group_id, &member_id))
	assert.False(t, create_time.IsZero())

	// These update tests check immutability
	{
		updateTests := []struct {
			testName string
			column   string
			value    any
			wantErr  bool
		}{
			{
				testName: "immutable managed group id",
				column:   "managed_group_id",
				value:    "z_yxwvutsrqp",
				wantErr:  true,
			},
			{
				testName: "immutable member_id",
				column:   "member_id",
				value:    "acct_1234567890",
				wantErr:  true,
			},
			{
				testName: "immutable creation time",
				column:   "create_time",
				value:    time.Now(),
				wantErr:  true,
			},
		}
		for _, tt := range updateTests {
			t.Run("update: "+tt.testName, func(t *testing.T) {
				assert := assert.New(t)
				_, err = rw.Exec(ctx, fmt.Sprintf("update auth_managed_group_member_account set %s = ? where managed_group_id = @group_id and member_id = @member_id", tt.column),
					[]any{
						sql.Named("group_id", managedGroupId),
						sql.Named("member_id", accountId),
					})
				assert.True(tt.wantErr == (err != nil))
			})
		}
	}

	// Read from the view to ensure we see it there
	rows, err = rw.Query(ctx, "select create_time, managed_group_id, member_id from auth_managed_group_member_account", nil)
	require.NoError(t, err)
	require.True(t, rows.Next())
	var view_create_time time.Time
	var view_managed_group_id, view_member_id string
	require.NoError(t, rows.Scan(&view_create_time, &view_managed_group_id, &view_member_id))
	assert.Equal(t, create_time, view_create_time)
	assert.Equal(t, managed_group_id, view_managed_group_id)
	assert.Equal(t, member_id, view_member_id)
}
