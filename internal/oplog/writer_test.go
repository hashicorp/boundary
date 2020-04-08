package oplog

import (
	"testing"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/watchtower/internal/oplog/oplog_test"
	"github.com/jinzhu/gorm"
	"gotest.tools/assert"
)

// Test_GormWriterCreate provides unit tests for GormWriter Create
func Test_GormWriterCreate(t *testing.T) {
	t.Parallel()
	startTest()
	cleanup, url := setup(t)
	defer cleanup()
	defer completeTest() // must come after the "defer cleanup()"
	db, err := test_dbconn(url)
	assert.NilError(t, err)
	defer db.Close()
	t.Run("valid", func(t *testing.T) {
		tx := db.Begin()
		defer tx.Rollback()
		w := GormWriter{tx}

		id, err := uuid.GenerateUUID()
		assert.NilError(t, err)

		user := oplog_test.TestUser{
			Name: "foo-" + id,
		}
		assert.NilError(t, w.Create(&user))

		var foundUser oplog_test.TestUser
		err = tx.Where("id = ?", user.Id).First(&foundUser).Error
		assert.NilError(t, err)
		assert.Equal(t, user.Name, foundUser.Name)
	})
	t.Run("nil tx", func(t *testing.T) {
		w := GormWriter{nil}

		id, err := uuid.GenerateUUID()
		assert.NilError(t, err)

		user := oplog_test.TestUser{
			Name: "foo-" + id,
		}
		err = w.Create(&user)
		assert.Check(t, err != nil)
		assert.Equal(t, err.Error(), "create Tx is nil")
	})
	t.Run("nil model", func(t *testing.T) {
		tx := db.Begin()
		defer tx.Rollback()
		w := GormWriter{tx}
		err = w.Create(nil)
		assert.Check(t, err != nil)
		assert.Equal(t, err.Error(), "create interface is nil")
	})
}

// Test_GormWriterDelete provides unit tests for GormWriter Delete
func Test_GormWriterDelete(t *testing.T) {
	t.Parallel()
	startTest()
	cleanup, url := setup(t)
	defer cleanup()
	defer completeTest() // must come after the "defer cleanup()"
	db, err := test_dbconn(url)
	assert.NilError(t, err)
	defer db.Close()
	t.Run("valid", func(t *testing.T) {
		tx := db.Begin()
		defer tx.Rollback()
		w := GormWriter{tx}

		id, err := uuid.GenerateUUID()
		assert.NilError(t, err)

		user := oplog_test.TestUser{
			Name: "foo-" + id,
		}
		assert.NilError(t, w.Create(&user))
		var foundUser oplog_test.TestUser
		err = tx.Where("id = ?", user.Id).First(&foundUser).Error
		assert.NilError(t, err)

		assert.NilError(t, w.Delete(&user))
		err = tx.Where("id = ?", user.Id).First(&foundUser).Error
		assert.Check(t, err != nil)
		assert.Equal(t, err, gorm.ErrRecordNotFound)
	})
	t.Run("nil tx", func(t *testing.T) {
		w := GormWriter{nil}

		id, err := uuid.GenerateUUID()
		assert.NilError(t, err)

		user := oplog_test.TestUser{
			Name: "foo-" + id,
		}
		err = w.Delete(&user)
		assert.Check(t, err != nil)
		assert.Equal(t, err.Error(), "delete Tx is nil")
	})
	t.Run("nil model", func(t *testing.T) {
		tx := db.Begin()
		defer tx.Rollback()
		w := GormWriter{tx}
		err = w.Delete(nil)
		assert.Check(t, err != nil)
		assert.Equal(t, err.Error(), "delete interface is nil")
	})
}

// Test_GormWriterUpdate provides unit tests for GormWriter Update
func Test_GormWriterUpdate(t *testing.T) {
	t.Parallel()
	startTest()
	cleanup, url := setup(t)
	defer cleanup()
	defer completeTest() // must come after the "defer cleanup()"
	db, err := test_dbconn(url)
	assert.NilError(t, err)
	defer db.Close()
	t.Run("valid no fieldmask", func(t *testing.T) {
		tx := db.Begin()
		defer tx.Rollback()
		w := GormWriter{tx}

		id, err := uuid.GenerateUUID()
		assert.NilError(t, err)

		user := oplog_test.TestUser{
			Name: "foo-" + id,
		}
		assert.NilError(t, w.Create(&user))
		var foundUser oplog_test.TestUser
		err = tx.Where("id = ?", user.Id).First(&foundUser).Error
		assert.NilError(t, err)

		foundUser.Name = foundUser.Name + "_updated"
		assert.NilError(t, w.Update(&foundUser, nil))

		var updatedUser oplog_test.TestUser
		err = tx.Where("id = ?", user.Id).First(&updatedUser).Error
		assert.NilError(t, err)
		assert.Equal(t, foundUser.Name, updatedUser.Name)
	})
	t.Run("valid with fieldmask", func(t *testing.T) {
		tx := db.Begin()
		defer tx.Rollback()
		w := GormWriter{tx}

		id, err := uuid.GenerateUUID()
		assert.NilError(t, err)

		user := oplog_test.TestUser{
			Name: "foo-" + id,
		}
		assert.NilError(t, w.Create(&user))
		var foundUser oplog_test.TestUser
		err = tx.Where("id = ?", user.Id).First(&foundUser).Error
		assert.NilError(t, err)

		foundUser.Name = foundUser.Name + "_updated"
		assert.NilError(t, w.Update(&foundUser, []string{"Name"}))

		var updatedUser oplog_test.TestUser
		err = tx.Where("id = ?", user.Id).First(&updatedUser).Error
		assert.NilError(t, err)
		assert.Equal(t, foundUser.Name, updatedUser.Name)
	})
	t.Run("valid with incorrect fieldmask", func(t *testing.T) {
		tx := db.Begin()
		defer tx.Rollback()
		w := GormWriter{tx}

		id, err := uuid.GenerateUUID()
		assert.NilError(t, err)

		user := oplog_test.TestUser{
			Name: "foo-" + id,
		}
		assert.NilError(t, w.Create(&user))
		var foundUser oplog_test.TestUser
		err = tx.Where("id = ?", user.Id).First(&foundUser).Error
		assert.NilError(t, err)

		foundUser.Name = foundUser.Name + "_updated"
		assert.NilError(t, w.Update(&foundUser, []string{"PhoneNumber"}))

		var updatedUser oplog_test.TestUser
		err = tx.Where("id = ?", user.Id).First(&updatedUser).Error
		assert.NilError(t, err)
		assert.Check(t, updatedUser.Name != foundUser.Name+"_updated")
	})
	t.Run("nil tx", func(t *testing.T) {
		w := GormWriter{nil}

		id, err := uuid.GenerateUUID()
		assert.NilError(t, err)

		user := oplog_test.TestUser{
			Name: "foo-" + id,
		}
		err = w.Update(&user, nil)
		assert.Check(t, err != nil)
		assert.Equal(t, err.Error(), "update Tx is nil")
	})
	t.Run("nil model", func(t *testing.T) {
		tx := db.Begin()
		defer tx.Rollback()
		w := GormWriter{tx}
		err = w.Update(nil, nil)
		assert.Check(t, err != nil)
		assert.Equal(t, err.Error(), "update interface is nil")
	})
}
