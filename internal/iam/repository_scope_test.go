package iam

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/golang/protobuf/ptypes"
	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/watchtower/internal/db"
	iam_store "github.com/hashicorp/watchtower/internal/iam/store"
	"github.com/hashicorp/watchtower/internal/oplog"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"
)

func Test_Repository_CreateScope(t *testing.T) {
	t.Parallel()
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer func() {
		if err := cleanup(); err != nil {
			t.Error(err)
		}
	}()
	assert := assert.New(t)
	defer func() {
		if err := conn.Close(); err != nil {
			t.Error(err)
		}
	}()

	t.Run("valid-scope", func(t *testing.T) {
		rw := db.New(conn)
		wrapper := db.TestWrapper(t)
		repo, err := NewRepository(rw, rw, wrapper)
		assert.NoError(err)
		id, err := uuid.GenerateUUID()
		assert.NoError(err)

		s, err := NewOrganization(WithName(id))
		assert.NoError(err)
		s, err = repo.CreateScope(context.Background(), s)
		assert.NoError(err)
		assert.NotNil(s)
		assert.NotEmpty(s.GetPublicId())
		assert.Equal(s.GetName(), id)

		foundScope, err := repo.LookupScope(context.Background(), s.PublicId)
		assert.NoError(err)
		assert.True(proto.Equal(foundScope, s))

		err = db.TestVerifyOplog(t, rw, s.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second))
		assert.NoError(err)
	})
	t.Run("dup-org-names", func(t *testing.T) {
		rw := db.New(conn)
		wrapper := db.TestWrapper(t)
		repo, err := NewRepository(rw, rw, wrapper)
		assert.NoError(err)
		id, err := uuid.GenerateUUID()
		assert.NoError(err)

		s, err := NewOrganization(WithName(id))
		assert.NoError(err)
		s, err = repo.CreateScope(context.Background(), s)
		assert.NoError(err)
		assert.NotNil(s)
		assert.NotEmpty(s.GetPublicId())
		assert.Equal(s.GetName(), id)

		s2, err := NewOrganization(WithName(id))
		assert.NoError(err)
		s2, err = repo.CreateScope(context.Background(), s2)
		assert.Error(err)
		assert.Nil(s2)
	})
	t.Run("dup-proj-names", func(t *testing.T) {
		rw := db.New(conn)
		wrapper := db.TestWrapper(t)
		repo, err := NewRepository(rw, rw, wrapper)
		assert.NoError(err)
		id, err := uuid.GenerateUUID()
		assert.NoError(err)

		s, err := NewOrganization(WithName(id))
		assert.NoError(err)
		s, err = repo.CreateScope(context.Background(), s)
		assert.NoError(err)
		assert.NotNil(s)
		assert.NotEmpty(s.GetPublicId())
		assert.Equal(s.GetName(), id)

		p, err := NewProject(s.PublicId, WithName(id))
		assert.NoError(err)
		p, err = repo.CreateScope(context.Background(), p)
		assert.NoError(err)
		assert.NotEmpty(p.PublicId)

		p2, err := NewProject(s.PublicId, WithName(id))
		assert.NoError(err)
		p2, err = repo.CreateScope(context.Background(), p2)
		assert.Error(err)
		assert.Nil(p2)
	})
}

func Test_Repository_UpdateScope(t *testing.T) {
	t.Parallel()
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer func() {
		if err := cleanup(); err != nil {
			t.Error(err)
		}
	}()
	assert := assert.New(t)
	defer func() {
		if err := conn.Close(); err != nil {
			t.Error(err)
		}
	}()

	t.Run("valid-scope", func(t *testing.T) {
		rw := db.New(conn)
		wrapper := db.TestWrapper(t)
		repo, err := NewRepository(rw, rw, wrapper)
		assert.NoError(err)
		id, err := uuid.GenerateUUID()
		assert.NoError(err)

		s, err := NewOrganization(WithName(id))
		assert.NoError(err)
		s, err = repo.CreateScope(context.Background(), s)
		assert.NoError(err)
		assert.NotNil(s)
		assert.NotEmpty(s.GetPublicId())
		assert.Equal(s.GetName(), id)

		foundScope, err := repo.LookupScope(context.Background(), s.PublicId)
		assert.NoError(err)
		assert.True(proto.Equal(foundScope, s))

		err = db.TestVerifyOplog(t, rw, s.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second))
		assert.NoError(err)

		s.Name = id
		s.Description = "desc-id" // not in the field mask paths
		s, updatedRows, err := repo.UpdateScope(context.Background(), s, []string{"Name"})
		assert.NoError(err)
		assert.Equal(1, updatedRows)
		assert.NotNil(s)
		assert.Equal(s.GetName(), id)
		assert.Empty(foundScope.GetDescription()) // should  be "" after update in db

		foundScope, err = repo.LookupScope(context.Background(), s.PublicId)
		assert.NoError(err)
		assert.Equal(foundScope.GetPublicId(), s.GetPublicId())
		assert.Empty(foundScope.GetDescription())

		err = db.TestVerifyOplog(t, rw, s.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second))
		assert.NoError(err)
	})
	t.Run("bad-parent-scope", func(t *testing.T) {
		rw := db.New(conn)
		wrapper := db.TestWrapper(t)
		repo, err := NewRepository(rw, rw, wrapper)
		assert.NoError(err)
		id, err := uuid.GenerateUUID()
		assert.NoError(err)

		s, err := NewOrganization(WithName(id))
		assert.NoError(err)
		s, err = repo.CreateScope(context.Background(), s)
		assert.NoError(err)
		assert.NotNil(s)
		assert.NotEmpty(s.GetPublicId())
		assert.Equal(s.GetName(), id)

		project, err := NewProject(s.PublicId)
		assert.NoError(err)
		project, err = repo.CreateScope(context.Background(), project)
		assert.NoError(err)
		assert.NotNil(project)

		project.ParentId = project.PublicId
		project, updatedRows, err := repo.UpdateScope(context.Background(), project, []string{"ParentId"})
		assert.Error(err)
		assert.Nil(project)
		assert.Equal(0, updatedRows)
		assert.Equal("update scope: you cannot change a scope's parent: invalid field mask", err.Error())
	})
}

func Test_Repository_LookupScope(t *testing.T) {
	t.Parallel()
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer func() {
		if err := cleanup(); err != nil {
			t.Error(err)
		}
	}()
	defer func() {
		if err := conn.Close(); err != nil {
			t.Error(err)
		}
	}()
	assert := assert.New(t)

	t.Run("found-and-not-found", func(t *testing.T) {
		rw := db.New(conn)
		wrapper := db.TestWrapper(t)
		repo, err := NewRepository(rw, rw, wrapper)
		assert.NoError(err)
		id, err := uuid.GenerateUUID()
		assert.NoError(err)

		s, err := NewOrganization(WithName(id))
		assert.NoError(err)
		s, err = repo.CreateScope(context.Background(), s)
		assert.NoError(err)
		assert.NotNil(s)
		assert.NotEmpty(s.GetPublicId())
		assert.Equal(s.GetName(), id)

		foundScope, err := repo.LookupScope(context.Background(), s.PublicId)
		assert.NoError(err)
		assert.True(proto.Equal(foundScope, s))

		invalidId, err := uuid.GenerateUUID()
		assert.NoError(err)
		notFoundById, err := repo.LookupScope(context.Background(), invalidId)
		assert.NoError(err)
		assert.Nil(notFoundById)
	})
}

func Test_Repository_DeleteScope(t *testing.T) {
	t.Parallel()
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer func() {
		if err := cleanup(); err != nil {
			t.Error(err)
		}
	}()
	assert := assert.New(t)
	defer func() {
		if err := conn.Close(); err != nil {
			t.Error(err)
		}
	}()
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo, err := NewRepository(rw, rw, wrapper)
	assert.NoError(err)
	t.Run("valid-with-public-id", func(t *testing.T) {
		s, err := NewOrganization()
		assert.NoError(err)
		s, err = repo.CreateScope(context.Background(), s)
		assert.NoError(err)
		assert.NotNil(s)
		assert.NotEmpty(s.GetPublicId())

		foundScope, err := repo.LookupScope(context.Background(), s.PublicId)
		assert.NoError(err)
		assert.Equal(foundScope.GetPublicId(), s.GetPublicId())

		rowsDeleted, err := repo.DeleteScope(context.Background(), s.PublicId)
		assert.NoError(err)
		assert.Equal(1, rowsDeleted)

		err = db.TestVerifyOplog(t, rw, s.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_DELETE), db.WithCreateNotBefore(10*time.Second))
		assert.NoError(err)

		foundScope, err = repo.LookupScope(context.Background(), s.PublicId)
		assert.NoError(err)
		assert.Nil(foundScope)

	})
	t.Run("valid-with-bad-id", func(t *testing.T) {
		invalidId, err := uuid.GenerateUUID()
		assert.NoError(err)
		foundScope, err := repo.LookupScope(context.Background(), invalidId)
		assert.NoError(err)
		assert.Nil(foundScope)
		rowsDeleted, err := repo.DeleteScope(context.Background(), invalidId)
		assert.NoError(err) // no error is expected if the resource isn't in the db
		assert.Equal(0, rowsDeleted)
	})
}

func TestRepository_UpdateScope(t *testing.T) {
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	now := &iam_store.Timestamp{Timestamp: ptypes.TimestampNow()}
	id := testId(t)
	defer func() {
		if err := cleanup(); err != nil {
			t.Error(err)
		}
	}()
	defer func() {
		if err := conn.Close(); err != nil {
			t.Error(err)
		}
	}()
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
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
			wantErrMsg:      "update scope: missing scope: nil parameter",
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
			wantErrMsg:      "update scope: empty field mask",
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
			wantErrMsg:      "update scope: you cannot change a scope's parent: invalid field mask",
			wantNullFields:  nil,
		},
		{
			name: "type",
			args: args{
				scope: &Scope{
					Scope: &iam_store.Scope{
						Name:        "type" + id,
						Description: "",
						Type:        ProjectScope.String(),
						CreateTime:  now,
						UpdateTime:  now,
						PublicId:    publicId,
					},
				},
				fieldMaskPaths: []string{"Type", "CreateTime", "UpdateTime", "PublicId"},
			},
			wantUpdatedRows: 0,
			wantErr:         true,
			wantErrMsg:      "update scope: empty field mask",
			wantNullFields:  nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			r := &Repository{
				reader:  rw,
				writer:  rw,
				wrapper: wrapper,
			}
			org := testOrg(t, conn, tt.name+"-orig-"+id, "orig-"+id)
			if tt.args.scope != nil {
				tt.args.scope.PublicId = org.PublicId
			}
			updatedScope, rowsUpdated, err := r.UpdateScope(context.Background(), tt.args.scope, tt.args.fieldMaskPaths, tt.args.opt...)
			if tt.wantErr {
				assert.Error(err)
				assert.Equal(tt.wantUpdatedRows, rowsUpdated)
				assert.Equal(tt.wantErrMsg, err.Error())
				return
			}
			assert.NoError(err)
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
			assert.NoError(err)
			assert.Equal(org.PublicId, foundScope.PublicId)
			assert.Equal(tt.wantName, foundScope.Name)
			assert.Equal(tt.wantDescription, foundScope.Description)
			assert.NotEqual(now, foundScope.CreateTime)
			assert.NotEqual(now, foundScope.UpdateTime)
		})
	}
	t.Run("dup-name", func(t *testing.T) {
		assert := assert.New(t)
		r := &Repository{
			reader:  rw,
			writer:  rw,
			wrapper: wrapper,
		}
		id := testId(t)
		_ = testOrg(t, conn, id, id)
		org2 := testOrg(t, conn, "dup-"+id, id)
		org2.Name = id
		updatedScope, rowsUpdated, err := r.UpdateScope(context.Background(), org2, []string{"Name"})
		assert.Error(err)
		assert.Equal(0, rowsUpdated, "updated rows should be 0")
		assert.Nil(updatedScope, "scope should be nil")
	})
}
