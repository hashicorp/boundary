package iam

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/watchtower/internal/db"
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
	defer conn.Close()

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
	defer conn.Close()

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
		assert.Equal("failed to update scope: update: vet for write failed you cannot change a scope's parent", err.Error())
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
	assert := assert.New(t)
	defer conn.Close()

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
	defer conn.Close()
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
