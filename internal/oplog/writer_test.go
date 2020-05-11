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
	cleanup, db := setup(t)
	defer cleanup()
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
		err := w.Create(nil)
		assert.Check(t, err != nil)
		assert.Equal(t, err.Error(), "create interface is nil")
	})
}

// Test_GormWriterDelete provides unit tests for GormWriter Delete
func Test_GormWriterDelete(t *testing.T) {
	cleanup, db := setup(t)
	defer cleanup()
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
		err := w.Delete(nil)
		assert.Check(t, err != nil)
		assert.Equal(t, err.Error(), "delete interface is nil")
	})
}

// Test_GormWriterUpdate provides unit tests for GormWriter Update
func Test_GormWriterUpdate(t *testing.T) {
	cleanup, db := setup(t)
	defer cleanup()
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
		err := w.Update(nil, nil)
		assert.Check(t, err != nil)
		assert.Equal(t, err.Error(), "update interface is nil")
	})
}

// Test_GormWriterHasTable provides unit tests for GormWriter HasTable
func Test_GormWriterHasTable(t *testing.T) {
	cleanup, db := setup(t)
	defer cleanup()
	defer db.Close()
	w := GormWriter{Tx: db}

	t.Run("success", func(t *testing.T) {
		ok := w.hasTable("oplog_test_user")
		assert.Equal(t, ok, true)
	})
	t.Run("no table", func(t *testing.T) {
		badTableName, err := uuid.GenerateUUID()
		assert.NilError(t, err)
		ok := w.hasTable(badTableName)
		assert.Equal(t, ok, false)
	})
	t.Run("blank table name", func(t *testing.T) {
		ok := w.hasTable("")
		assert.Equal(t, ok, false)
	})
}

// Test_GormWriterCreateTable provides unit tests for GormWriter CreateTable
func Test_GormWriterCreateTable(t *testing.T) {
	cleanup, db := setup(t)
	defer cleanup()
	defer db.Close()
	t.Run("success", func(t *testing.T) {
		w := GormWriter{Tx: db}
		suffix, err := uuid.GenerateUUID()
		assert.NilError(t, err)
		u := &oplog_test.TestUser{}
		newTableName := u.TableName() + "_" + suffix
		defer func() { assert.NilError(t, w.dropTableIfExists(newTableName)) }()
		err = w.createTableLike(u.TableName(), newTableName)
		assert.NilError(t, err)
	})
	t.Run("call twice", func(t *testing.T) {
		w := GormWriter{Tx: db}
		suffix, err := uuid.GenerateUUID()
		assert.NilError(t, err)
		u := &oplog_test.TestUser{}
		newTableName := u.TableName() + "_" + suffix
		defer func() { assert.NilError(t, w.dropTableIfExists(newTableName)) }()
		err = w.createTableLike(u.TableName(), newTableName)
		assert.NilError(t, err)

		// should be an error to create the same table twice
		err = w.createTableLike(u.TableName(), newTableName)
		assert.Check(t, err != nil)
		assert.Error(t, err, err.Error(), nil)
	})
	t.Run("empty existing", func(t *testing.T) {
		w := GormWriter{Tx: db}
		suffix, err := uuid.GenerateUUID()
		assert.NilError(t, err)
		u := &oplog_test.TestUser{}
		newTableName := u.TableName() + "_" + suffix
		defer func() { assert.NilError(t, w.dropTableIfExists(newTableName)) }()
		err = w.createTableLike("", newTableName)
		assert.Check(t, err != nil)
		assert.Error(t, err, err.Error(), nil)
		assert.Equal(t, err.Error(), "error existingTableName is empty string")
	})
	t.Run("blank name", func(t *testing.T) {
		w := GormWriter{Tx: db}
		u := &oplog_test.TestUser{}
		err := w.createTableLike(u.TableName(), "")
		assert.Check(t, err != nil)
		assert.Error(t, err, err.Error(), nil)
		assert.Equal(t, err.Error(), "error newTableName is empty string")
	})
}

// Test_GormWriterDropTableIfExists provides unit tests for GormWriter DropTableIfExists
func Test_GormWriterDropTableIfExists(t *testing.T) {
	cleanup, db := setup(t)
	defer cleanup()
	defer db.Close()
	t.Run("success", func(t *testing.T) {
		w := GormWriter{Tx: db}
		suffix, err := uuid.GenerateUUID()
		assert.NilError(t, err)
		u := &oplog_test.TestUser{}
		newTableName := u.TableName() + "_" + suffix
		err = w.createTableLike(u.TableName(), newTableName)
		assert.NilError(t, err)
		defer func() { assert.NilError(t, w.dropTableIfExists(newTableName)) }()
	})

	t.Run("success with blank", func(t *testing.T) {
		w := GormWriter{Tx: db}
		err := w.dropTableIfExists("")
		assert.Check(t, err != nil)
		assert.Equal(t, err.Error(), "cannot drop table whose name is an empty string")
	})
}
