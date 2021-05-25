package migration

import (
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/servers/controller"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_ManagedGroupTable(t *testing.T) {
	t.Parallel()
	tc := controller.NewTestController(t, nil)
	defer tc.Shutdown()

	db := tc.DbConn().DB()
	var err error

	managedGroupId := "a_bcdefghijk"
	defaultPasswordAuthMethodId := "ampw_1234567890"
	defaultOidcAuthMethodId := "amoidc_1234567890"
	globalScopeId := "global"

	insertTests := []struct {
		testName     string
		publicId     string
		authMethodId string
		scopeId      string
		wantErr      bool
	}{
		{
			testName:     "invalid auth method",
			publicId:     managedGroupId,
			authMethodId: "amoid_1234567890",
			scopeId:      globalScopeId,
			wantErr:      true,
		},
		{
			testName:     "invalid scope",
			publicId:     managedGroupId,
			authMethodId: defaultOidcAuthMethodId,
			scopeId:      "globule",
			wantErr:      true,
		},
		{
			testName:     "invalid scope",
			publicId:     managedGroupId,
			authMethodId: defaultOidcAuthMethodId,
			scopeId:      "globule",
			wantErr:      true,
		},
		{
			testName:     "valid",
			publicId:     managedGroupId,
			authMethodId: defaultOidcAuthMethodId,
			scopeId:      globalScopeId,
			wantErr:      false,
		},
	}
	for _, tt := range insertTests {
		t.Run("insert: "+tt.testName, func(t *testing.T) {
			require := require.New(t)
			_, err = db.Exec("insert into auth_managed_group values ($1, $2, $3)",
				tt.publicId,
				tt.authMethodId,
				tt.scopeId)
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
			testName: "immutable scope",
			column:   "scope_id",
			value:    "globule",
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
			_, err = db.Exec(fmt.Sprintf("update auth_managed_group set %s = $1 where public_id = $2", tt.column), tt.value, tt.publicId)
			assert.True(tt.wantErr == (err != nil))
		})
	}
}

func Test_OidcManagedGroupTable(t *testing.T) {
	t.Parallel()
	tc := controller.NewTestController(t, nil)
	defer tc.Shutdown()

	db := tc.DbConn().DB()
	var err error

	managedGroupId := "a_bcdefghijk"
	defaultPasswordAuthMethodId := "ampw_1234567890"
	defaultOidcAuthMethodId := "amoidc_1234567890"
	globalScopeId := "global"
	name := "this is the name"
	filter := "this is a filter"

	// The first set of tests is for initial insertion
	{
		insertTests := []struct {
			testName     string
			publicId     string
			authMethodId string
			scopeId      string
			name         string
			filter       string
			wantErr      bool
		}{
			{
				testName:     "null filter",
				publicId:     managedGroupId,
				authMethodId: "amoid_1234567890",
				scopeId:      globalScopeId,
				name:         name,
				filter:       "",
				wantErr:      true,
			},
			{
				testName:     "invalid auth method",
				publicId:     managedGroupId,
				authMethodId: defaultPasswordAuthMethodId,
				scopeId:      globalScopeId,
				name:         name,
				filter:       filter,
				wantErr:      true,
			},
			{
				testName:     "invalid scope",
				publicId:     managedGroupId,
				authMethodId: defaultOidcAuthMethodId,
				scopeId:      "globule",
				name:         name,
				filter:       filter,
				wantErr:      true,
			},
			{
				testName:     "valid",
				publicId:     managedGroupId,
				authMethodId: defaultOidcAuthMethodId,
				scopeId:      globalScopeId,
				name:         name,
				filter:       filter,
				wantErr:      false,
			},
			{
				testName:     "duplicate public id",
				publicId:     managedGroupId,
				authMethodId: defaultOidcAuthMethodId,
				scopeId:      globalScopeId,
				name:         name,
				filter:       filter,
				wantErr:      true,
			},
			{
				testName:     "duplicate name",
				publicId:     "z_yxwvutsrqp",
				authMethodId: defaultOidcAuthMethodId,
				scopeId:      globalScopeId,
				name:         name,
				filter:       filter,
				wantErr:      true,
			},
		}
		for _, tt := range insertTests {
			t.Run("insert: "+tt.testName, func(t *testing.T) {
				require := require.New(t)
				_, err = db.Exec("insert into auth_oidc_managed_group (public_id, auth_method_id, scope_id, name, filter) values ($1, $2, $3, $4, $5)",
					tt.publicId,
					tt.authMethodId,
					tt.scopeId,
					tt.name,
					tt.filter)
				require.True(tt.wantErr == (err != nil))
			})
		}
	}

	// Read some values to validate that things were set automatically
	rows, err := db.Query("select create_time, update_time, version from auth_oidc_managed_group")
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
			value    interface{}
			wantErr  bool
		}{
			{
				testName: "immutable public id",
				column:   "public_id",
				value:    "z_yxwvutsrqp",
				wantErr:  true,
			},
			{
				testName: "immutable scope",
				column:   "scope_id",
				value:    "globule",
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
				_, err = db.Exec(fmt.Sprintf("update auth_oidc_managed_group set %s = $1 where public_id = $2", tt.column), tt.value, managedGroupId)
				require.True(tt.wantErr == (err != nil))
			})
		}
	}

	// Read values again to validate that things were updated automatically
	rows, err = db.Query("select create_time, update_time, version from auth_oidc_managed_group")
	require.NoError(t, err)
	require.True(t, rows.Next())
	var updated_create_time, updated_update_time time.Time
	require.NoError(t, rows.Scan(&updated_create_time, &updated_update_time, &version))
	assert.Equal(t, create_time, updated_create_time)
	assert.NotEqual(t, update_time, updated_update_time)
	assert.Equal(t, 2, version)

	// Finally, read values from auth_managed_group to ensure it was populated automatically
	rows, err = db.Query("select public_id, auth_method_id, scope_id from auth_managed_group")
	require.NoError(t, err)
	require.True(t, rows.Next())
	var public_id, auth_method_id, scope_id string
	require.NoError(t, rows.Scan(&public_id, &auth_method_id, &scope_id))
	assert.Equal(t, managedGroupId, public_id)
	assert.Equal(t, defaultOidcAuthMethodId, auth_method_id)
}

func Test_AuthManagedGroupMemberAccountTable(t *testing.T) {
	t.Parallel()
	tc := controller.NewTestController(t, nil)
	defer tc.Shutdown()

	db := tc.DbConn().DB()
	var err error

	managedGroupId := "a_bcdefghijk"
	defaultOidcAuthMethodId := "amoidc_1234567890"
	globalScopeId := "global"
	name := "this is the name"
	filter := "this is a filter"

	// Insert valid data in auth_oidc_managed_group to use for the following tests
	_, err = db.Exec("insert into auth_oidc_managed_group (public_id, auth_method_id, scope_id, name, filter) values ($1, $2, $3, $4, $5)",
		managedGroupId,
		defaultOidcAuthMethodId,
		globalScopeId,
		name,
		filter)
	require.NoError(t, err)

	// Fetch a valid account  ID to use in insertion
	rows, err := db.Query("select public_id from auth_account limit 1")
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
				_, err = db.Exec("insert into auth_managed_group_member_account (managed_group_id, member_id) values ($1, $2)",
					tt.managedGroupId,
					tt.memberId)
				assert.True(tt.wantErr == (err != nil))
			})
		}
	}

	// Read some values to validate that things were set automatically
	rows, err = db.Query("select create_time from auth_managed_group_member_account")
	require.NoError(t, err)
	require.True(t, rows.Next())
	var create_time time.Time
	require.NoError(t, rows.Scan(&create_time))
	assert.False(t, create_time.IsZero())

	// These update tests check immutability
	{
		updateTests := []struct {
			testName string
			column   string
			value    interface{}
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
				_, err = db.Exec(fmt.Sprintf("update auth_managed_grou_member_account set %s = $1 where managed_group_id = $2 and member_id = $3", tt.column), managedGroupId, accountId)
				assert.True(tt.wantErr == (err != nil))
			})
		}
	}
}
