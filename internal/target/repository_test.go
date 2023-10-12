// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package target

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/perms"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/go-kms-wrapping/extras/kms/v2/migrations"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewRepository(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, conn, wrapper)
	type args struct {
		r    db.Reader
		w    db.Writer
		kms  *kms.Kms
		opts []Option
	}
	tests := []struct {
		name          string
		args          args
		want          *Repository
		wantErr       bool
		wantErrString string
	}{
		{
			name: "valid",
			args: args{
				r:   rw,
				w:   rw,
				kms: testKms,
			},
			want: &Repository{
				reader:       rw,
				writer:       rw,
				kms:          testKms,
				defaultLimit: db.DefaultLimit,
			},
			wantErr: false,
		},
		{
			name: "nil-kms",
			args: args{
				r:   rw,
				w:   rw,
				kms: nil,
			},
			want:          nil,
			wantErr:       true,
			wantErrString: "target.NewRepository: nil kms: parameter violation: error #100",
		},
		{
			name: "nil-writer",
			args: args{
				r:   rw,
				w:   nil,
				kms: testKms,
			},
			want:          nil,
			wantErr:       true,
			wantErrString: "target.NewRepository: nil writer: parameter violation: error #100",
		},
		{
			name: "nil-reader",
			args: args{
				r:   nil,
				w:   rw,
				kms: testKms,
			},
			want:          nil,
			wantErr:       true,
			wantErrString: "target.NewRepository: nil reader: parameter violation: error #100",
		},
		{
			name: "WithPermissions sets object to `permissions`",
			args: args{
				r:   rw,
				w:   rw,
				kms: testKms,
				opts: []Option{
					WithPermissions([]perms.Permission{
						{ScopeId: "test1", Resource: resource.Target},
						{ScopeId: "test2", Resource: resource.Target},
					}),
				},
			},
			want: &Repository{
				reader:       rw,
				writer:       rw,
				kms:          testKms,
				defaultLimit: db.DefaultLimit,
				permissions: []perms.Permission{
					{ScopeId: "test1", Resource: resource.Target},
					{ScopeId: "test2", Resource: resource.Target},
				},
			},
			wantErr: false,
		},
		{
			name: "Don't accept permissions that aren't for the Target resource",
			args: args{
				r:   rw,
				w:   rw,
				kms: testKms,
				opts: []Option{
					WithPermissions([]perms.Permission{
						{ScopeId: "test1", Resource: resource.Target},
						{ScopeId: "test2", Resource: resource.Host},
					}),
				},
			},
			want:          nil,
			wantErr:       true,
			wantErrString: "target.NewRepository: permission for incorrect resource found: parameter violation: error #100",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := NewRepository(context.Background(), tt.args.r, tt.args.w, tt.args.kms, tt.args.opts...)
			if tt.wantErr {
				require.Error(err)
				assert.Equal(tt.wantErrString, err.Error())
				return
			}
			require.NoError(err)
			assert.NotNil(got)
			assert.Equal(tt.want, got)
		})
	}
}

func TestRepositoryListPermissionWhereClauses(t *testing.T) {
	tests := []struct {
		name     string
		perms    []perms.Permission
		expWhere []string
		expArgs  []any
	}{
		{
			name:     "nilPerms",
			perms:    nil,
			expWhere: []string{},
			expArgs:  []any{},
		},
		{
			name:     "emptyPerms",
			perms:    []perms.Permission{},
			expWhere: []string{},
			expArgs:  []any{},
		},
		{
			name: "noListActionPerms",
			perms: []perms.Permission{
				{
					ScopeId: "scope_a",
					Action:  action.Create,
				},
				{
					ScopeId: "scope_b",
					Action:  action.Read,
				},
				{
					ScopeId: "scope_c",
					Action:  action.Delete,
				},
			},
			expWhere: []string{},
			expArgs:  []any{},
		},
		{
			name: "onePermissionAllResources",
			perms: []perms.Permission{
				{
					ScopeId: "scope_a",
					Action:  action.List,
				},
			},
			expWhere: []string{"(project_id = @project_id_1)"},
			expArgs:  []any{sql.Named("project_id_1", "scope_a")},
		},
		{
			name: "onePermissionAllResourcesNonListIgnored",
			perms: []perms.Permission{
				{
					ScopeId: "scope_a",
					Action:  action.List,
				},
				{
					ScopeId: "scope_b",
					Action:  action.Create,
				},
			},
			expWhere: []string{"(project_id = @project_id_1)"},
			expArgs:  []any{sql.Named("project_id_1", "scope_a")},
		},
		{
			name: "onePermissionResourceIds",
			perms: []perms.Permission{
				{
					ScopeId:     "scope_a",
					Action:      action.List,
					ResourceIds: []string{"resourceid1", "resourceid2"},
				},
			},
			expWhere: []string{"(project_id = @project_id_1 and public_id = any(@public_id_1))"},
			expArgs: []any{
				sql.Named("project_id_1", "scope_a"),
				sql.Named("public_id_1", "{resourceid1,resourceid2}"),
			},
		},
		{
			name: "multiplePermissionsAllResources",
			perms: []perms.Permission{
				{ScopeId: "scope_a", Action: action.List},
				{ScopeId: "scope_b", Action: action.List},
				{ScopeId: "scope_c", Action: action.List},
				{ScopeId: "scope_d", Action: action.List},
			},
			expWhere: []string{
				"(project_id = @project_id_1)",
				"(project_id = @project_id_2)",
				"(project_id = @project_id_3)",
				"(project_id = @project_id_4)",
			},
			expArgs: []any{
				sql.Named("project_id_1", "scope_a"),
				sql.Named("project_id_2", "scope_b"),
				sql.Named("project_id_3", "scope_c"),
				sql.Named("project_id_4", "scope_d"),
			},
		},
		{
			name: "multiplePermissionsResourceIds",
			perms: []perms.Permission{
				{
					ScopeId:     "scope_a",
					Action:      action.List,
					ResourceIds: []string{"resourceid1", "resourceid2"},
				},
				{
					ScopeId:     "scope_b",
					Action:      action.List,
					ResourceIds: []string{"resourceid3", "resourceid4"},
				},
			},
			expWhere: []string{
				"(project_id = @project_id_1 and public_id = any(@public_id_1))",
				"(project_id = @project_id_2 and public_id = any(@public_id_2))",
			},
			expArgs: []any{
				sql.Named("project_id_1", "scope_a"),
				sql.Named("project_id_2", "scope_b"),
				sql.Named("public_id_1", "{resourceid1,resourceid2}"),
				sql.Named("public_id_2", "{resourceid3,resourceid4}"),
			},
		},
		{
			name: "multiplePermissionsMix",
			perms: []perms.Permission{
				{
					ScopeId:     "scope_a",
					Action:      action.List,
					ResourceIds: []string{"resourceid1", "resourceid2"},
				},
				{
					ScopeId:     "scope_b",
					Action:      action.List,
					ResourceIds: []string{"resourceid3", "resourceid4"},
				},
				{ScopeId: "scope_c", Action: action.List},
				{ScopeId: "scope_d", Action: action.List},
			},
			expWhere: []string{
				"(project_id = @project_id_1 and public_id = any(@public_id_1))",
				"(project_id = @project_id_2 and public_id = any(@public_id_2))",
				"(project_id = @project_id_3)",
				"(project_id = @project_id_4)",
			},
			expArgs: []any{
				sql.Named("project_id_1", "scope_a"),
				sql.Named("public_id_1", "{resourceid1,resourceid2}"),
				sql.Named("project_id_2", "scope_b"),
				sql.Named("public_id_2", "{resourceid3,resourceid4}"),
				sql.Named("project_id_3", "scope_c"),
				sql.Named("project_id_4", "scope_d"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := Repository{}
			repo.permissions = tt.perms

			where, args := repo.listPermissionWhereClauses()
			require.ElementsMatch(t, tt.expWhere, where)
			require.ElementsMatch(t, tt.expArgs, args)
		})
	}
}

func Test_listDeletedIds(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, mock := db.TestSetupWithMock(t)
	wrapper := db.TestWrapper(t)
	mock.ExpectQuery(
		`SELECT \* FROM "kms_schema_version" WHERE 1=1 ORDER BY "kms_schema_version"\."version" LIMIT 1`,
	).WillReturnRows(sqlmock.NewRows([]string{"version", "create_time"}).AddRow(migrations.Version, time.Now()))
	mock.ExpectQuery(
		`SELECT \* FROM "kms_oplog_schema_version" WHERE 1=1 ORDER BY "kms_oplog_schema_version"."version" LIMIT 1`,
	).WillReturnRows(sqlmock.NewRows([]string{"version", "create_time"}).AddRow(migrations.Version, time.Now()))
	testKms := kms.TestKms(t, conn, wrapper)

	rw := db.New(conn)
	repo, err := NewRepository(ctx, rw, rw, testKms)
	require.NoError(t, err)
	now := time.Now().Truncate(time.Microsecond)
	before := now.AddDate(-1, 0, 0)

	t.Run("returns no entries when no entries in db", func(t *testing.T) {
		mock.ExpectBegin()
		mock.ExpectQuery(
			`SELECT`,
		).WithArgs(before).WillReturnRows(sqlmock.NewRows([]string{"public_id", "delete_time"}))
		mock.ExpectQuery(
			`select current_timestamp`,
		).WillReturnRows(sqlmock.NewRows([]string{"current_timestamp"}).AddRow(now))
		mock.ExpectCommit()
		deletedIds, ttime, err := repo.listDeletedIds(ctx, before)
		require.NoError(t, err)
		require.Empty(t, deletedIds)
		assert.True(t, ttime.Equal(now))
	})

	t.Run("returns 1 entry when 1 entry in db", func(t *testing.T) {
		id := "tcp_1234567890"
		mock.ExpectBegin()
		mock.ExpectQuery(
			`SELECT`,
		).WithArgs(before).WillReturnRows(sqlmock.NewRows([]string{"public_id", "delete_time"}).AddRow(id, now.Add(-time.Hour)))
		mock.ExpectQuery(
			`select current_timestamp`,
		).WillReturnRows(sqlmock.NewRows([]string{"current_timestamp"}).AddRow(now))
		mock.ExpectCommit()
		deletedIds, ttime, err := repo.listDeletedIds(ctx, before)
		require.NoError(t, err)
		require.Equal(t, []string{id}, deletedIds)
		assert.True(t, ttime.Equal(now))
	})

	t.Run("errors when query errors", func(t *testing.T) {
		mock.ExpectBegin()
		mock.ExpectQuery(
			`SELECT`,
		).WithArgs(before).WillReturnError(fmt.Errorf("query error"))
		mock.ExpectRollback()
		_, _, err = repo.listDeletedIds(ctx, before)
		require.ErrorContains(t, err, "query error")
	})
}

func Test_estimatedCount(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, mock := db.TestSetupWithMock(t)
	wrapper := db.TestWrapper(t)
	mock.ExpectQuery(
		`SELECT \* FROM "kms_schema_version" WHERE 1=1 ORDER BY "kms_schema_version"\."version" LIMIT 1`,
	).WillReturnRows(sqlmock.NewRows([]string{"version", "create_time"}).AddRow(migrations.Version, time.Now()))
	mock.ExpectQuery(
		`SELECT \* FROM "kms_oplog_schema_version" WHERE 1=1 ORDER BY "kms_oplog_schema_version"."version" LIMIT 1`,
	).WillReturnRows(sqlmock.NewRows([]string{"version", "create_time"}).AddRow(migrations.Version, time.Now()))
	testKms := kms.TestKms(t, conn, wrapper)

	rw := db.New(conn)
	repo, err := NewRepository(ctx, rw, rw, testKms)
	require.NoError(t, err)

	t.Run("returns 0 when db returns 0", func(t *testing.T) {
		mock.ExpectQuery(
			`select`,
		).WillReturnRows(sqlmock.NewRows([]string{"estimate"}).AddRow(0))
		numItems, err := repo.estimatedCount(ctx)
		require.NoError(t, err)
		assert.Equal(t, 0, numItems)
	})

	t.Run("returns 1 when db returns 1", func(t *testing.T) {
		mock.ExpectQuery(
			`select`,
		).WillReturnRows(sqlmock.NewRows([]string{"estimate"}).AddRow(1))
		numItems, err := repo.estimatedCount(ctx)
		require.NoError(t, err)
		assert.Equal(t, 1, numItems)
	})

	t.Run("errors when query errors", func(t *testing.T) {
		mock.ExpectQuery(
			`select`,
		).WillReturnError(fmt.Errorf("query error"))
		_, err = repo.estimatedCount(ctx)
		require.ErrorContains(t, err, "query error")
	})
}
