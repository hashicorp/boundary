// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package iam

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	iam_store "github.com/hashicorp/boundary/internal/iam/store"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func Test_Repository_Scope_Create(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	user := TestUser(t, repo, "global")

	t.Run("valid-scope", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		id := testId(t)
		s, err := NewOrg(ctx, WithName(id))
		require.NoError(err)
		s, err = repo.CreateScope(ctx, s, "")
		require.NoError(err)
		require.NotNil(s)
		assert.NotEmpty(s.GetPublicId())
		assert.Equal(s.GetName(), id)

		foundScope, err := repo.LookupScope(ctx, s.PublicId)
		require.NoError(err)
		assert.True(proto.Equal(foundScope, s))

		err = db.TestVerifyOplog(t, rw, s.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second))
		assert.NoError(err)
	})
	t.Run("valid-scope-withPublicId", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		publicId, err := newScopeId(ctx, scope.Org)
		require.NoError(err)
		s, err := NewOrg(ctx)
		require.NoError(err)

		s, err = repo.CreateScope(ctx, s, "", WithPublicId(publicId))
		require.NoError(err)
		require.NotNil(s)
		assert.Equal(publicId, s.GetPublicId())
		foundScope, err := repo.LookupScope(ctx, s.PublicId)
		require.NoError(err)
		assert.True(proto.Equal(foundScope, s))

		err = db.TestVerifyOplog(t, rw, s.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second))
		assert.NoError(err)
	})
	t.Run("dup-org-names", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		id := testId(t)

		s, err := NewOrg(ctx, WithName(id))
		require.NoError(err)

		s, err = repo.CreateScope(context.Background(), s, "")
		require.NoError(err)
		require.NotNil(s)
		assert.NotEmpty(s.GetPublicId())
		assert.Equal(s.GetName(), id)

		s2, err := NewOrg(ctx, WithName(id))
		require.NoError(err)
		s2, err = repo.CreateScope(context.Background(), s2, "")
		require.Error(err)
		assert.Nil(s2)
	})
	t.Run("dup-proj-names", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		id := testId(t)

		s, err := NewOrg(ctx, WithName(id))
		require.NoError(err)
		s, err = repo.CreateScope(context.Background(), s, "")
		require.NoError(err)
		require.NotNil(s)
		assert.NotEmpty(s.GetPublicId())
		assert.Equal(s.GetName(), id)

		p, err := NewProject(ctx, s.PublicId, WithName(id))
		require.NoError(err)
		p, err = repo.CreateScope(context.Background(), p, "")
		require.NoError(err)
		require.NotEmpty(p.PublicId)

		p2, err := NewProject(ctx, s.PublicId, WithName(id))
		require.NoError(err)
		p2, err = repo.CreateScope(context.Background(), p2, "")
		assert.Error(err)
		assert.Nil(p2)
	})
	for _, skipCreate := range []bool{false, true} {
		t.Run(fmt.Sprintf("skipping-role-creation-%t", skipCreate), func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			id := testId(t)
			s, err := NewOrg(ctx, WithName(id))
			require.NoError(err)
			s, err = repo.CreateScope(context.Background(), s, user.GetPublicId(), WithSkipAdminRoleCreation(skipCreate), WithSkipDefaultRoleCreation(skipCreate))
			require.NoError(err)
			require.NotNil(s)
			assert.NotEmpty(s.GetPublicId())
			assert.Equal(s.GetName(), id)

			foundScope, err := repo.LookupScope(context.Background(), s.PublicId)
			require.NoError(err)
			assert.True(proto.Equal(foundScope, s))

			foundRoles, _, err := repo.listRoles(context.Background(), []string{foundScope.GetPublicId()})
			require.NoError(err)
			numFound := 2
			if skipCreate {
				numFound = 0
			}
			assert.Len(foundRoles, numFound)
		})
	}
}

func Test_Repository_Scope_Update(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	t.Run("valid-scope", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		id := testId(t)

		s := testOrg(t, repo, id, "")
		assert.Equal(id, s.Name)

		foundScope, err := repo.LookupScope(ctx, s.PublicId)
		require.NoError(err)
		assert.Empty(foundScope.GetDescription()) // should  be "" after update in db
		assert.True(proto.Equal(foundScope, s))
		assert.Empty(s.StoragePolicyId)

		err = db.TestVerifyOplog(t, rw, s.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second))
		require.NoError(err)

		s.Name = "foo" + id
		s.Description = "desc-id" // not in the field mask paths
		s, updatedRows, err := repo.UpdateScope(ctx, s, s.Version, []string{"Name"})
		require.NoError(err)
		assert.Equal(1, updatedRows)
		require.NotNil(s)
		assert.Equal("foo"+id, s.GetName())
		assert.Empty(s.StoragePolicyId)
		// TODO: This isn't empty because of ICU-490 -- when that is resolved, fix this
		// assert.Empty(s.GetDescription())
		foundScope, err = repo.LookupScope(ctx, s.PublicId)
		require.NoError(err)
		assert.Equal(foundScope.GetPublicId(), s.GetPublicId())
		assert.Empty(foundScope.GetDescription())

		err = db.TestVerifyOplog(t, rw, s.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second))
		assert.NoError(err)

		s.Name = "test2"
		s.Description = "desc-id-2"
		s, updatedRows, err = repo.UpdateScope(ctx, s, s.Version, []string{"Name", "Description"})
		require.NoError(err)
		assert.Equal(1, updatedRows)
		require.NotNil(s)
		assert.Equal("test2", s.GetName())
		assert.Equal("desc-id-2", s.GetDescription())
	})
	t.Run("bad-parent-scope", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		id := testId(t)

		s := testOrg(t, repo, id, "")
		assert.Equal(id, s.Name)

		project, err := NewProject(ctx, s.PublicId)
		require.NoError(err)
		project, err = repo.CreateScope(ctx, project, "")
		require.NoError(err)
		require.NotNil(project)

		project.ParentId = project.PublicId
		project, updatedRows, err := repo.UpdateScope(ctx, project, 1, []string{"ParentId"})
		require.Error(err)
		assert.Nil(project)
		assert.Equal(0, updatedRows)
		assert.Contains(err.Error(), "iam.(Repository).UpdateScope: you cannot change a scope's parent: parameter violation: error #103")
	})
}

func Test_Repository_Scope_Lookup(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	t.Run("found-and-not-found", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		id := testId(t)

		s := testOrg(t, repo, id, "")
		require.NotEmpty(s.GetPublicId())
		assert.Equal(s.GetName(), id)

		foundScope, err := repo.LookupScope(context.Background(), s.PublicId)
		require.NoError(err)
		assert.True(proto.Equal(foundScope, s))
		assert.Empty(s.StoragePolicyId)

		invalidId := testId(t)
		notFoundById, err := repo.LookupScope(context.Background(), invalidId)
		assert.NoError(err)
		assert.Nil(notFoundById)
	})
}

func Test_Repository_Scope_Delete(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	t.Run("valid-with-public-id", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		s, _ := TestScopes(t, repo)
		foundScope, err := repo.LookupScope(context.Background(), s.PublicId)
		require.NoError(err)
		assert.Equal(foundScope.GetPublicId(), s.GetPublicId())

		rowsDeleted, err := repo.DeleteScope(context.Background(), s.PublicId)
		require.NoError(err)
		assert.Equal(1, rowsDeleted)

		err = db.TestVerifyOplog(t, rw, s.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_DELETE), db.WithCreateNotBefore(10*time.Second))
		assert.NoError(err)

		foundScope, err = repo.LookupScope(context.Background(), s.PublicId)
		require.NoError(err)
		assert.Nil(foundScope)
	})
	t.Run("valid-with-bad-id", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		invalidId := testId(t)
		foundScope, err := repo.LookupScope(context.Background(), invalidId)
		require.NoError(err)
		require.Nil(foundScope)
		rowsDeleted, err := repo.DeleteScope(context.Background(), invalidId)
		require.NoError(err) // no error is expected if the resource isn't in the db
		assert.Equal(0, rowsDeleted)
	})
}

func TestRepository_UpdateScope(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	now := &timestamp.Timestamp{Timestamp: timestamppb.Now()}
	id := testId(t)
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	publicId := testPublicId(t, "o")

	type args struct {
		scope          *Scope
		fieldMaskPaths []string
		opt            []Option
	}
	tests := []struct {
		name            string
		args            args
		wantName        string
		wantDescription string
		wantUpdatedRows int
		wantErr         bool
		wantErrMsg      string
		wantNullFields  []string
	}{
		{
			name: "valid-scope",
			args: args{
				scope: &Scope{
					Scope: &iam_store.Scope{
						Name:        "valid-scope" + id,
						Description: "",
						CreateTime:  now,
						UpdateTime:  now,
						PublicId:    publicId,
					},
				},
				fieldMaskPaths: []string{"Name", "Description", "CreateTime", "UpdateTime", "PublicId"},
			},
			wantName:        "valid-scope" + id,
			wantDescription: "",
			wantUpdatedRows: 1,
			wantErr:         false,
			wantErrMsg:      "",
			wantNullFields:  []string{"Description"},
		},
		{
			name: "nil-resource",
			args: args{
				scope:          nil,
				fieldMaskPaths: []string{"Name"},
			},
			wantUpdatedRows: 0,
			wantErr:         true,
			wantErrMsg:      "iam.(Repository).UpdateScope: missing scope: parameter violation: error #100",
			wantNullFields:  nil,
		},
		{
			name: "no-updates",
			args: args{
				scope: &Scope{
					Scope: &iam_store.Scope{
						Name:        "no-updates" + id,
						Description: "updated" + id,
						CreateTime:  now,
						UpdateTime:  now,
						PublicId:    publicId,
					},
				},
				fieldMaskPaths: []string{"CreateTime"},
			},
			wantUpdatedRows: 0,
			wantErr:         true,
			wantErrMsg:      "iam.(Repository).UpdateScope: empty field mask, parameter violation: error #104",
			wantNullFields:  nil,
		},
		{
			name: "no-null",
			args: args{
				scope: &Scope{
					Scope: &iam_store.Scope{
						Name:        "no-null" + id,
						Description: "updated" + id,
						CreateTime:  now,
						UpdateTime:  now,
						PublicId:    publicId,
					},
				},
				fieldMaskPaths: []string{"Name"},
			},
			wantName:        "no-null" + id,
			wantDescription: "orig-" + id,
			wantUpdatedRows: 1,
			wantErr:         false,
			wantErrMsg:      "",
			wantNullFields:  nil,
		},
		{
			name: "only-null",
			args: args{
				scope: &Scope{
					Scope: &iam_store.Scope{
						Name:        "",
						Description: "",
						CreateTime:  now,
						UpdateTime:  now,
						PublicId:    publicId,
					},
				},
				fieldMaskPaths: []string{"Name", "Description"},
			},
			wantName:        "",
			wantDescription: "",
			wantUpdatedRows: 1,
			wantErr:         false,
			wantErrMsg:      "",
			wantNullFields:  nil,
		},
		{
			name: "parent",
			args: args{
				scope: &Scope{
					Scope: &iam_store.Scope{
						Name:        "parent" + id,
						Description: "",
						ParentId:    publicId,
						CreateTime:  now,
						UpdateTime:  now,
						PublicId:    publicId,
					},
				},
				fieldMaskPaths: []string{"ParentId", "CreateTime", "UpdateTime", "PublicId"},
			},
			wantName:        "parent-orig-" + id,
			wantDescription: "orig-" + id,
			wantUpdatedRows: 0,
			wantErr:         true,
			wantErrMsg:      "iam.(Repository).UpdateScope: you cannot change a scope's parent: parameter violation: error #103",
			wantNullFields:  nil,
		},
		{
			name: "type",
			args: args{
				scope: &Scope{
					Scope: &iam_store.Scope{
						Name:        "type" + id,
						Description: "",
						Type:        scope.Project.String(),
						CreateTime:  now,
						UpdateTime:  now,
						PublicId:    publicId,
					},
				},
				fieldMaskPaths: []string{"Type", "CreateTime", "UpdateTime", "PublicId"},
			},
			wantUpdatedRows: 0,
			wantErr:         true,
			wantErrMsg:      "am.(Repository).UpdateScope: empty field mask, parameter violation: error #104",
			wantNullFields:  nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			org := testOrg(t, repo, tt.name+"-orig-"+id, "orig-"+id)
			if tt.args.scope != nil {
				tt.args.scope.PublicId = org.PublicId
			}
			updatedScope, rowsUpdated, err := repo.UpdateScope(context.Background(), tt.args.scope, 1, tt.args.fieldMaskPaths, tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
				assert.Equal(tt.wantUpdatedRows, rowsUpdated)
				assert.Contains(err.Error(), tt.wantErrMsg)
				return
			}
			require.NoError(err)
			assert.Equal(tt.wantUpdatedRows, rowsUpdated)
			if tt.wantUpdatedRows > 0 {
				err = db.TestVerifyOplog(t, rw, org.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second))
				assert.NoError(err)
			}

			foundScope := AllocScope()
			foundScope.PublicId = updatedScope.PublicId
			where := "public_id = ?"
			for _, f := range tt.wantNullFields {
				where = fmt.Sprintf("%s and %s is null", where, f)
			}
			err = rw.LookupWhere(context.Background(), &foundScope, where, []any{org.PublicId})
			require.NoError(err)
			assert.Equal(org.PublicId, foundScope.PublicId)
			assert.Equal(tt.wantName, foundScope.Name)
			assert.Equal(tt.wantDescription, foundScope.Description)
			assert.NotEqual(now, foundScope.CreateTime)
			assert.NotEqual(now, foundScope.UpdateTime)
		})
	}
	t.Run("dup-name", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		r := &Repository{
			reader: rw,
			writer: rw,
			kms:    repo.kms,
		}
		id := testId(t)
		_ = testOrg(t, repo, id, id)
		org2 := testOrg(t, repo, "dup-"+id, id)
		org2.Name = id
		updatedScope, rowsUpdated, err := r.UpdateScope(context.Background(), org2, 1, []string{"Name"})
		require.Error(err)
		assert.Equal(0, rowsUpdated, "updated rows should be 0")
		assert.Nil(updatedScope, "scope should be nil")
	})
}

func Test_Repository_ListScopes(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	const testLimit = 10
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper, WithLimit(testLimit))
	type args struct {
		opt []Option
	}
	tests := []struct {
		name      string
		createCnt int
		args      args
		wantCnt   int
		wantErr   bool
	}{
		{
			name:      "default-limit",
			createCnt: repo.defaultLimit + 1,
			args:      args{},
			wantCnt:   repo.defaultLimit,
			wantErr:   false,
		},
		{
			name:      "custom-limit",
			createCnt: repo.defaultLimit + 1,
			args: args{
				opt: []Option{WithLimit(3)},
			},
			wantCnt: 3,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			db.TestDeleteWhere(t, conn, func() any {
				i := AllocScope()
				return &i
			}(), "type = 'org'")

			testOrgs := []*Scope{}
			for i := 0; i < tt.createCnt; i++ {
				testOrgs = append(testOrgs, testOrg(t, repo, "", ""))
			}
			assert.Equal(tt.createCnt, len(testOrgs))
			got, ttime, err := repo.listScopes(context.Background(), []string{"global"}, tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
				return
			}
			require.NoError(err)
			assert.Equal(tt.wantCnt, len(got))
			// Transaction timestamp should be within ~10 seconds of now
			assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
			assert.True(time.Now().After(ttime.Add(-10 * time.Second)))
		})
	}

	t.Run("withStartPageAfter", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		ctx := context.Background()

		// Create 10 projects in a new org
		org := testOrg(t, repo, "", "")
		for i := 0; i < 10; i++ {
			_ = testProject(t, repo, org.GetPublicId())
		}

		page1, ttime, err := repo.listScopes(ctx, []string{org.GetPublicId()}, WithLimit(2))
		require.NoError(err)
		require.Len(page1, 2)
		// Transaction timestamp should be within ~10 seconds of now
		assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
		assert.True(time.Now().After(ttime.Add(-10 * time.Second)))
		page2, ttime, err := repo.listScopes(ctx, []string{org.GetPublicId()}, WithLimit(2), WithStartPageAfterItem(page1[1]))
		require.NoError(err)
		require.Len(page2, 2)
		assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
		assert.True(time.Now().After(ttime.Add(-10 * time.Second)))
		for _, item := range page1 {
			assert.NotEqual(item.GetPublicId(), page2[0].GetPublicId())
			assert.NotEqual(item.GetPublicId(), page2[1].GetPublicId())
		}
		page3, ttime, err := repo.listScopes(ctx, []string{org.GetPublicId()}, WithLimit(2), WithStartPageAfterItem(page2[1]))
		require.NoError(err)
		require.Len(page3, 2)
		assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
		assert.True(time.Now().After(ttime.Add(-10 * time.Second)))
		for _, item := range page2 {
			assert.NotEqual(item.GetPublicId(), page3[0].GetPublicId())
			assert.NotEqual(item.GetPublicId(), page3[1].GetPublicId())
		}
		page4, ttime, err := repo.listScopes(ctx, []string{org.GetPublicId()}, WithLimit(2), WithStartPageAfterItem(page3[1]))
		require.NoError(err)
		assert.Len(page4, 2)
		assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
		assert.True(time.Now().After(ttime.Add(-10 * time.Second)))
		for _, item := range page3 {
			assert.NotEqual(item.GetPublicId(), page4[0].GetPublicId())
			assert.NotEqual(item.GetPublicId(), page4[1].GetPublicId())
		}
		page5, ttime, err := repo.listScopes(ctx, []string{org.GetPublicId()}, WithLimit(2), WithStartPageAfterItem(page4[1]))
		require.NoError(err)
		assert.Len(page5, 2)
		assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
		assert.True(time.Now().After(ttime.Add(-10 * time.Second)))
		for _, item := range page4 {
			assert.NotEqual(item.GetPublicId(), page5[0].GetPublicId())
			assert.NotEqual(item.GetPublicId(), page5[1].GetPublicId())
		}
		page6, ttime, err := repo.listScopes(ctx, []string{org.GetPublicId()}, WithLimit(2), WithStartPageAfterItem(page5[1]))
		require.NoError(err)
		assert.Empty(page6)
		assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
		assert.True(time.Now().After(ttime.Add(-10 * time.Second)))

		// Create 2 new Scopes
		newP1 := testProject(t, repo, org.GetPublicId())
		newP2 := testProject(t, repo, org.GetPublicId())

		// since it will return newest to oldest, we get page1[1] first
		page7, ttime, err := repo.listScopesRefresh(
			ctx,
			time.Now().Add(-1*time.Second),
			[]string{org.GetPublicId()},
			WithLimit(1),
		)
		require.NoError(err)
		require.Len(page7, 1)
		require.Equal(page7[0].GetPublicId(), newP2.GetPublicId())
		assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
		assert.True(time.Now().After(ttime.Add(-10 * time.Second)))

		page8, ttime, err := repo.listScopesRefresh(
			context.Background(),
			time.Now().Add(-1*time.Second),
			[]string{org.GetPublicId()},
			WithLimit(1),
			WithStartPageAfterItem(page7[0]),
		)
		require.NoError(err)
		require.Len(page8, 1)
		require.Equal(page8[0].GetPublicId(), newP1.GetPublicId())
		assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
		assert.True(time.Now().After(ttime.Add(-10 * time.Second)))
	})
}

func TestRepository_ListScopes_Multiple_Scopes(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)

	db.TestDeleteWhere(t, conn, func() any { i := AllocScope(); return &i }(), "public_id != 'global'")

	const numPerScope = 10
	var total int
	var scopeIds []string
	for i := 0; i < numPerScope; i++ {
		scopeIds = append(scopeIds, testOrg(t, repo, "", "").PublicId)
		total++
		for j := 0; j < numPerScope; j++ {
			testProject(t, repo, scopeIds[i])
			total++
		}
	}
	// Add global to the mix
	scopeIds = append(scopeIds, "global")

	got, _, err := repo.listScopes(context.Background(), scopeIds)
	require.NoError(t, err)
	assert.Equal(t, total, len(got))
}

func Test_Repository_ListRecursive(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	var testOrgs []*Scope
	var testProjects []*Scope
	const subPerScope = 5
	for i := 0; i < subPerScope; i++ {
		org := testOrg(t, repo, fmt.Sprint(i), "")
		testOrgs = append(testOrgs, org)
		for j := 0; j < subPerScope; j++ {
			testProjects = append(testProjects, testProject(t, repo, org.PublicId, WithName(fmt.Sprintf("%d-%d", i, j))))
		}
	}
	tests := []struct {
		name        string
		rootScopeId string
		wantCnt     int
		wantErr     bool
	}{
		{
			name:        "global",
			rootScopeId: "global",
			wantCnt:     1 + len(testOrgs) + len(testProjects),
		},
		{
			name:        "org",
			rootScopeId: testOrgs[0].PublicId,
			wantCnt:     1 + subPerScope,
		},
		{
			name:        "project",
			rootScopeId: testProjects[16].PublicId,
			wantCnt:     1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := repo.ListScopesRecursively(context.Background(), tt.rootScopeId)
			if tt.wantErr {
				require.Error(err)
				return
			}
			require.NoError(err)
			assert.Equal(tt.wantCnt, len(got))
		})
	}
}

func Test_listDeletedIds(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	org := TestOrg(t, repo)

	// Expect no entries at the start
	deletedIds, ttime, err := repo.listScopeDeletedIds(ctx, time.Now().AddDate(-1, 0, 0))
	require.NoError(t, err)
	require.Empty(t, deletedIds)

	// Transaction time should be within ~10 seconds of now
	now := time.Now()
	assert.True(t, ttime.Add(-10*time.Second).Before(now))
	assert.True(t, ttime.Add(10*time.Second).After(now))

	// Delete a scope
	p := TestProject(t, repo, org.GetPublicId())
	_, err = repo.DeleteScope(ctx, p.PublicId)
	require.NoError(t, err)

	// Expect a single entry
	deletedIds, ttime, err = repo.listScopeDeletedIds(ctx, time.Now().AddDate(-1, 0, 0))
	require.NoError(t, err)
	require.Equal(t, []string{p.PublicId}, deletedIds)
	now = time.Now()
	assert.True(t, ttime.Add(-10*time.Second).Before(now))
	assert.True(t, ttime.Add(10*time.Second).After(now))

	// Try again with the time set to now, expect no entries
	deletedIds, ttime, err = repo.listScopeDeletedIds(ctx, time.Now())
	require.NoError(t, err)
	require.Empty(t, deletedIds)
	now = time.Now()
	assert.True(t, ttime.Add(-10*time.Second).Before(now))
	assert.True(t, ttime.Add(10*time.Second).After(now))
}

func Test_estimatedScopeCount(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	sqlDb, err := conn.SqlDB(ctx)
	require.NoError(t, err)

	// Check total entries at start, expect 1 (global)
	numItems, err := repo.estimatedScopeCount(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, numItems)

	// Create a scope, expect 2 entries
	org := TestOrg(t, repo)
	// Run analyze to update estimate
	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(t, err)
	numItems, err = repo.estimatedScopeCount(ctx)
	require.NoError(t, err)
	assert.Equal(t, 2, numItems)

	// Delete the scope, expect 1 again
	_, err = repo.DeleteScope(ctx, org.PublicId)
	require.NoError(t, err)
	// Run analyze to update estimate
	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(t, err)
	numItems, err = repo.estimatedScopeCount(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, numItems)
}
