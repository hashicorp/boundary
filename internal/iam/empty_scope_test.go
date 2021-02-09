package iam

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/jinzhu/gorm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testEmptyScope(t *testing.T, conn *gorm.DB) *Scope {
	t.Helper()
	require := require.New(t)

	w := db.New(conn)
	s := allocScope()
	s.PublicId = "empty"
	err := w.LookupById(context.Background(), &s)
	require.NoError(err)
	require.Equal(s.Type, scope.Empty.String())
	return &s
}

func TestEmptyScope_Update(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	w := db.New(conn)
	t.Run("type-update-not-allowed", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		s := testEmptyScope(t, conn)
		s.Type = scope.Project.String()
		updatedRows, err := w.Update(context.Background(), s, []string{"Type"}, nil)
		require.Error(err)
		assert.Equal(0, updatedRows)
	})
	t.Run("name-update-not-allowed", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		s := testEmptyScope(t, conn)
		s.Name = "blahblah"
		updatedRows, err := w.Update(context.Background(), s, []string{"Name"}, nil)
		require.Error(err)
		assert.Equal(0, updatedRows)
	})
	t.Run("description-update-not-allowed", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		s := testEmptyScope(t, conn)
		s.Description = "blahblah"
		updatedRows, err := w.Update(context.Background(), s, []string{"Description"}, nil)
		require.Error(err)
		assert.Equal(0, updatedRows)
	})
}

func TestEmptyScope_Delete(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	w := db.New(conn)
	t.Run("delete-not-allowed", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		s := testEmptyScope(t, conn)
		rows, err := w.Delete(context.Background(), &s)
		require.Error(err)
		assert.Equal(0, rows)
	})
}
