package iam

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/golang/protobuf/ptypes"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	iam_store "github.com/hashicorp/boundary/internal/iam/store"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func Test_Repository_Scope_Create(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	user := TestUser(t, repo, "global")

	t.Run("valid-scope", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		id := testId(t)
		s, err := NewOrg(WithName(id))
		require.NoError(err)
		s, err = repo.CreateScope(context.Background(), s, "")
		require.NoError(err)
		require.NotNil(s)
		assert.NotEmpty(s.GetPublicId())
		assert.Equal(s.GetName(), id)

		foundScope, err := repo.LookupScope(context.Background(), s.PublicId)
		require.NoError(err)
		assert.True(proto.Equal(foundScope, s))

		err = db.TestVerifyOplog(t, rw, s.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second))
		assert.NoError(err)
	})
	t.Run("valid-scope-withPublicId", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		publicId, err := newScopeId(scope.Org)
		require.NoError(err)
		s, err := NewOrg()
		require.NoError(err)

		s, err = repo.CreateScope(context.Background(), s, "", WithPublicId(publicId))
		require.NoError(err)
		require.NotNil(s)
		assert.Equal(publicId, s.GetPublicId())
		foundScope, err := repo.LookupScope(context.Background(), s.PublicId)
		require.NoError(err)
		assert.True(proto.Equal(foundScope, s))

		err = db.TestVerifyOplog(t, rw, s.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second))
		assert.NoError(err)
	})
	t.Run("dup-org-names", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		id := testId(t)

		s, err := NewOrg(WithName(id))
		require.NoError(err)

		s, err = repo.CreateScope(context.Background(), s, "")
		require.NoError(err)
		require.NotNil(s)
		assert.NotEmpty(s.GetPublicId())
		assert.Equal(s.GetName(), id)

		s2, err := NewOrg(WithName(id))
		require.NoError(err)
		s2, err = repo.CreateScope(context.Background(), s2, "")
		require.Error(err)
		assert.Nil(s2)
	})
	t.Run("dup-proj-names", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		id := testId(t)

		s, err := NewOrg(WithName(id))
		require.NoError(err)
		s, err = repo.CreateScope(context.Background(), s, "")
		require.NoError(err)
		require.NotNil(s)
		assert.NotEmpty(s.GetPublicId())
		assert.Equal(s.GetName(), id)

		p, err := NewProject(s.PublicId, WithName(id))
		require.NoError(err)
		p, err = repo.CreateScope(context.Background(), p, "")
		require.NoError(err)
		require.NotEmpty(p.PublicId)

		p2, err := NewProject(s.PublicId, WithName(id))
		require.NoError(err)
		p2, err = repo.CreateScope(context.Background(), p2, "")
		assert.Error(err)
		assert.Nil(p2)
	})
	for _, skipCreate := range []bool{false, true} {
		t.Run(fmt.Sprintf("skipping-role-creation-%t", skipCreate), func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			id := testId(t)
			s, err := NewOrg(WithName(id))
			require.NoError(err)
			s, err = repo.CreateScope(context.Background(), s, user.GetPublicId(), WithSkipAdminRoleCreation(skipCreate), WithSkipDefaultRoleCreation(skipCreate))
			require.NoError(err)
			require.NotNil(s)
			assert.NotEmpty(s.GetPublicId())
			assert.Equal(s.GetName(), id)

			foundScope, err := repo.LookupScope(context.Background(), s.PublicId)
			require.NoError(err)
			assert.True(proto.Equal(foundScope, s))

			foundRoles, err := repo.ListRoles(context.Background(), []string{foundScope.GetPublicId()})
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
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	t.Run("valid-scope", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		id := testId(t)

		s := testOrg(t, repo, id, "")
		assert.Equal(id, s.Name)

		foundScope, err := repo.LookupScope(context.Background(), s.PublicId)
		require.NoError(err)
		assert.Empty(foundScope.GetDescription()) // should  be "" after update in db
		assert.True(proto.Equal(foundScope, s))

		err = db.TestVerifyOplog(t, rw, s.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second))
		require.NoError(err)

		s.Name = "foo" + id
		s.Description = "desc-id" // not in the field mask paths
		s, updatedRows, err := repo.UpdateScope(context.Background(), s, 1, []string{"Name"})
		require.NoError(err)
		assert.Equal(1, updatedRows)
		require.NotNil(s)
		assert.Equal("foo"+id, s.GetName())
		// TODO: This isn't empty because of ICU-490 -- when that is resolved, fix this
		// assert.Empty(s.GetDescription())

		foundScope, err = repo.LookupScope(context.Background(), s.PublicId)
		require.NoError(err)
		assert.Equal(foundScope.GetPublicId(), s.GetPublicId())
		assert.Empty(foundScope.GetDescription())

		err = db.TestVerifyOplog(t, rw, s.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second))
		assert.NoError(err)

		s.Name = "test2"
		s.Description = "desc-id-2"
		s, updatedRows, err = repo.UpdateScope(context.Background(), s, 2, []string{"Name", "Description"})
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

		project, err := NewProject(s.PublicId)
		require.NoError(err)
		project, err = repo.CreateScope(context.Background(), project, "")
		require.NoError(err)
		require.NotNil(project)

		project.ParentId = project.PublicId
		project, updatedRows, err := repo.UpdateScope(context.Background(), project, 1, []string{"ParentId"})
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
	now := &timestamp.Timestamp{Timestamp: ptypes.TimestampNow()}
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

			foundScope := allocScope()
			foundScope.PublicId = updatedScope.PublicId
			where := "public_id = ?"
			for _, f := range tt.wantNullFields {
				where = fmt.Sprintf("%s and %s is null", where, f)
			}
			err = rw.LookupWhere(context.Background(), &foundScope, where, org.PublicId)
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
			name:      "no-limit",
			createCnt: repo.defaultLimit + 1,
			args: args{
				opt: []Option{WithLimit(-1)},
			},
			wantCnt: repo.defaultLimit + 1,
			wantErr: false,
		},
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
			require.NoError(conn.Where("type = 'org'").Delete(allocScope()).Error)
			testOrgs := []*Scope{}
			for i := 0; i < tt.createCnt; i++ {
				testOrgs = append(testOrgs, testOrg(t, repo, "", ""))
			}
			assert.Equal(tt.createCnt, len(testOrgs))
			got, err := repo.ListScopes(context.Background(), []string{"global"}, tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
				return
			}
			require.NoError(err)
			assert.Equal(tt.wantCnt, len(got))
		})
	}
}

func TestRepository_ListScopes_Multiple_Scopes(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)

	require.NoError(t, conn.Where("public_id != 'global'").Delete(allocScope()).Error)

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

	got, err := repo.ListScopes(context.Background(), scopeIds)
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
