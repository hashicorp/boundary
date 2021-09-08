package oplog

import (
	"testing"

	"github.com/hashicorp/boundary/internal/oplog/oplog_test"
	dbassert "github.com/hashicorp/dbassert/gorm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// Test_GormWriterCreate provides unit tests for GormWriter Create
func Test_GormWriterCreate(t *testing.T) {
	cleanup, db := setup(t)
	defer testCleanup(t, cleanup, db)
	t.Run("valid", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		tx := db.Begin()
		defer tx.Rollback()
		w := GormWriter{tx}
		user := oplog_test.TestUser{
			Name: "foo-" + testId(t),
		}
		require.NoError(w.Create(&user))

		foundUser := testFindUser(t, tx, user.Id)
		assert.Equal(user.Name, foundUser.Name)
	})
	t.Run("nil tx", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		w := GormWriter{nil}

		err := w.Create(&oplog_test.TestUser{})
		require.Error(err)

		assert.Equal("oplog.(GormWriter).Create: nil tx: parameter violation: error #100", err.Error())
	})
	t.Run("nil model", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		tx := db.Begin()
		defer tx.Rollback()
		w := GormWriter{tx}
		err := w.Create(nil)
		require.Error(err)
		assert.Equal("oplog.(GormWriter).Create: nil interface: parameter violation: error #100", err.Error())
	})
}

// Test_GormWriterDelete provides unit tests for GormWriter Delete
func Test_GormWriterDelete(t *testing.T) {
	cleanup, db := setup(t)
	defer testCleanup(t, cleanup, db)
	t.Run("valid", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		tx := db.Begin()
		defer tx.Rollback()
		w := GormWriter{tx}

		id := testId(t)
		user := testUser(t, db, "foo-"+id, "", "")
		foundUser := testFindUser(t, db, user.Id)

		require.NoError(w.Delete(&user))
		err := tx.Where("id = ?", user.Id).First(&foundUser).Error
		require.Error(err)
		assert.Equal(gorm.ErrRecordNotFound, err)
	})
	t.Run("nil tx", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		w := GormWriter{nil}
		err := w.Delete(&oplog_test.TestUser{})
		require.Error(err)
		assert.Equal("oplog.(GormWriter).Delete: nil tx: parameter violation: error #100", err.Error())
	})
	t.Run("nil model", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		tx := db.Begin()
		defer tx.Rollback()
		w := GormWriter{tx}
		err := w.Delete(nil)
		require.Error(err)
		assert.Equal("oplog.(GormWriter).Delete: nil interface: parameter violation: error #100", err.Error())
	})
}

// Test_GormWriterHasTable provides unit tests for GormWriter HasTable
func Test_GormWriterHasTable(t *testing.T) {
	cleanup, db := setup(t)
	defer testCleanup(t, cleanup, db)
	w := GormWriter{Tx: db}

	t.Run("success", func(t *testing.T) {
		assert := require.New(t)
		ok := w.hasTable("oplog_test_user")
		assert.Equal(ok, true)
	})
	t.Run("no table", func(t *testing.T) {
		assert := assert.New(t)
		badTableName := testId(t)
		ok := w.hasTable(badTableName)
		assert.Equal(ok, false)
	})
	t.Run("blank table name", func(t *testing.T) {
		assert := assert.New(t)
		ok := w.hasTable("")
		assert.Equal(ok, false)
	})
}

// Test_GormWriterCreateTable provides unit tests for GormWriter CreateTable
func Test_GormWriterCreateTable(t *testing.T) {
	cleanup, db := setup(t)
	defer testCleanup(t, cleanup, db)
	t.Run("success", func(t *testing.T) {
		assert := assert.New(t)
		w := GormWriter{Tx: db}
		suffix := testId(t)
		u := &oplog_test.TestUser{}
		newTableName := u.TableName() + "_" + suffix
		defer func() { assert.NoError(w.dropTableIfExists(newTableName)) }()
		err := w.createTableLike(u.TableName(), newTableName)
		assert.NoError(err)
	})
	t.Run("call twice", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		w := GormWriter{Tx: db}
		suffix := testId(t)
		u := &oplog_test.TestUser{}
		newTableName := u.TableName() + "_" + suffix
		defer func() { assert.NoError(w.dropTableIfExists(newTableName)) }()
		err := w.createTableLike(u.TableName(), newTableName)
		require.NoError(err)

		// should be an error to create the same table twice
		err = w.createTableLike(u.TableName(), newTableName)
		require.Error(err)
		assert.Error(err, err.Error(), nil)
	})
	t.Run("empty existing", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		w := GormWriter{Tx: db}
		suffix := testId(t)
		u := &oplog_test.TestUser{}
		newTableName := u.TableName() + "_" + suffix
		defer func() { assert.NoError(w.dropTableIfExists(newTableName)) }()
		err := w.createTableLike("", newTableName)
		require.Error(err)
		assert.Error(err, err.Error(), nil)
		assert.Equal("oplog.(GormWriter).createTableLike: missing existing table name: parameter violation: error #100", err.Error())
	})
	t.Run("blank name", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		w := GormWriter{Tx: db}
		u := &oplog_test.TestUser{}
		err := w.createTableLike(u.TableName(), "")
		require.Error(err)
		assert.Error(err, err.Error(), nil)
		assert.Equal("oplog.(GormWriter).createTableLike: missing new table name: parameter violation: error #100", err.Error())
	})
}

// Test_GormWriterDropTableIfExists provides unit tests for GormWriter DropTableIfExists
func Test_GormWriterDropTableIfExists(t *testing.T) {
	cleanup, db := setup(t)
	defer testCleanup(t, cleanup, db)
	t.Run("success", func(t *testing.T) {
		assert := assert.New(t)
		w := GormWriter{Tx: db}
		suffix := testId(t)

		u := &oplog_test.TestUser{}
		newTableName := u.TableName() + "_" + suffix

		assert.NoError(w.createTableLike(u.TableName(), newTableName))
		defer func() { assert.NoError(w.dropTableIfExists(newTableName)) }()
	})

	t.Run("success with blank", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		w := GormWriter{Tx: db}
		err := w.dropTableIfExists("")
		require.Error(err)
		assert.Equal("oplog.(GormWriter).dropTableIfExists: missing table name: parameter violation: error #100", err.Error())
	})
}

func TestGormWriter_Update(t *testing.T) {
	cleanup, db := setup(t)
	defer testCleanup(t, cleanup, db)
	id := testId(t)
	type fields struct {
		Tx *gorm.DB
	}
	type args struct {
		user           *oplog_test.TestUser
		fieldMaskPaths []string
		setToNullPaths []string
	}
	tests := []struct {
		name     string
		Tx       *gorm.DB
		args     args
		wantUser *oplog_test.TestUser
		wantErr  bool
	}{
		{
			name: "valid-fieldmask",
			Tx:   db,
			args: args{
				user: &oplog_test.TestUser{
					Name: "valid-fieldmask",
				},
				fieldMaskPaths: []string{"name"},
			},
			wantUser: &oplog_test.TestUser{
				Name:        "valid-fieldmask",
				Email:       id,
				PhoneNumber: id,
			},
			wantErr: false,
		},
		{
			name: "valid-setToNull",
			Tx:   db,
			args: args{
				user: &oplog_test.TestUser{
					Name: "valid-setToNull",
				},
				fieldMaskPaths: nil,
				setToNullPaths: []string{"name"},
			},
			wantUser: &oplog_test.TestUser{
				Name:        "",
				Email:       id,
				PhoneNumber: id,
			},
			wantErr: false,
		},
		{
			name: "valid-setToNull-and-fieldMask",
			Tx:   db,
			args: args{
				user: &oplog_test.TestUser{
					Email: "valid-setToNull-and-fieldMask",
				},
				fieldMaskPaths: []string{"email"},
				setToNullPaths: []string{"name"},
			},
			wantUser: &oplog_test.TestUser{
				Name:        "",
				Email:       "valid-setToNull-and-fieldMask",
				PhoneNumber: id,
			},
			wantErr: false,
		},
		{
			name: "no-field-mask",
			Tx:   db,
			args: args{
				user: &oplog_test.TestUser{
					Name: "no-field-mask",
				},
				fieldMaskPaths: []string{""},
			},
			wantErr: true,
		},
		{
			name: "nil-field-mask",
			Tx:   db,
			args: args{
				user: &oplog_test.TestUser{
					Name: "nil-field-mask",
				},
				fieldMaskPaths: nil,
			},
			wantErr: true,
		},
		{
			name: "nil-tx",
			Tx:   nil,
			args: args{
				user: &oplog_test.TestUser{
					Name: "nil-txt",
				},
				fieldMaskPaths: []string{"name"},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			underlyingDB, err := db.DB()
			require.NoError(err)
			dbassert := dbassert.New(t, underlyingDB, db.Dialector.Name())

			w := &GormWriter{
				Tx: tt.Tx,
			}
			u := testUser(t, db, id, id, id) // intentionally, not relying on tt.Tx
			u.Name = tt.args.user.Name
			u.Email = tt.args.user.Email
			u.PhoneNumber = tt.args.user.PhoneNumber
			err = w.Update(tt.args.user, tt.args.fieldMaskPaths, tt.args.setToNullPaths)
			if tt.wantErr {
				require.Error(err)
				return
			}
			require.NoError(err)
			var foundUser oplog_test.TestUser
			err = db.Where("id = ?", u.Id).First(&foundUser).Error
			require.NoError(err)
			tt.wantUser.Id = u.Id
			assert.Equal(tt.wantUser, &foundUser)
			for _, f := range tt.args.setToNullPaths {
				dbassert.IsNull(u, f)
			}
		})
	}
	t.Run("nil model", func(t *testing.T) {
		assert := assert.New(t)
		w := GormWriter{db}
		err := w.Create(nil)
		assert.Error(err)
	})
}
