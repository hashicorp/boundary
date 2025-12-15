// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package oplog

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/oplog/oplog_test"
	dbassert "github.com/hashicorp/dbassert/gorm"
	"github.com/hashicorp/go-dbw"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	_ "gorm.io/driver/postgres"
)

// Test_WriterCreate provides unit tests for Writer Create
func Test_WriterCreate(t *testing.T) {
	testCtx := context.Background()
	db, _ := setup(testCtx, t)
	t.Run("valid", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		tx, err := dbw.New(db).Begin(testCtx)
		require.NoError(err)
		defer func() {
			assert.NoError(tx.Rollback(testCtx))
		}()
		w := Writer{tx.DB()}
		user := oplog_test.TestUser{
			Name: "foo-" + testId(t),
		}
		require.NoError(dbw.New(w.DB).Create(testCtx, &user))

		foundUser := testFindUser(t, tx.DB(), user.Id)
		assert.Equal(user.Name, foundUser.Name)
	})
	t.Run("nil tx", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		w := Writer{}

		err := dbw.New(w.DB).Create(testCtx, &oplog_test.TestUser{})
		require.Error(err)
		assert.Contains(err.Error(), " missing underlying db: invalid parameter")
	})
	t.Run("nil model", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		tx, err := dbw.New(db).Begin(testCtx)
		require.NoError(err)
		defer func() {
			assert.NoError(tx.Rollback(testCtx))
		}()
		w := Writer{tx.DB()}
		err = dbw.New(w.DB).Create(testCtx, nil)
		require.Error(err)
		assert.Contains(err.Error(), "missing interface")
	})
}

// Test_WriterDelete provides unit tests for Writer Delete
func Test_WriterDelete(t *testing.T) {
	testCtx := context.Background()
	db, _ := setup(testCtx, t)
	t.Run("valid", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		tx, err := dbw.New(db).Begin(testCtx)
		require.NoError(err)
		defer func() {
			assert.NoError(tx.Rollback(testCtx))
		}()
		w := Writer{tx.DB()}

		id := testId(t)
		user := testUser(t, db, "foo-"+id, "", "")
		foundUser := testFindUser(t, db, user.Id)

		_, err = dbw.New(w.DB).Delete(testCtx, &user)
		require.NoError(err)
		err = dbw.New(w.DB).LookupWhere(testCtx, &foundUser, "id = ?", []any{user.Id})
		require.Error(err)
		assert.ErrorIs(err, dbw.ErrRecordNotFound)
	})
	t.Run("nil tx", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		w := Writer{}
		_, err := dbw.New(w.DB).Delete(testCtx, &oplog_test.TestUser{})
		require.Error(err)
		assert.Contains(err.Error(), "missing underlying db")
	})
	t.Run("nil model", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		tx, err := dbw.New(db).Begin(testCtx)
		require.NoError(err)
		defer tx.Rollback(testCtx)
		w := Writer{tx.DB()}
		_, err = dbw.New(w.DB).Delete(testCtx, nil)
		require.Error(err)
		assert.Contains(err.Error(), "missing interface")
	})
}

// TestWriter_hasTable provides unit tests for Writer HasTable
func TestWriter_hasTable(t *testing.T) {
	testCtx := context.Background()
	db, _ := setup(testCtx, t)
	w := Writer{db}

	t.Run("success", func(t *testing.T) {
		assert := require.New(t)
		ok, _ := w.hasTable(testCtx, "oplog_test_user")
		assert.Equal(true, ok)
	})
	t.Run("no table", func(t *testing.T) {
		assert := assert.New(t)
		badTableName := testId(t)
		ok, _ := w.hasTable(testCtx, badTableName)
		assert.Equal(ok, false)
	})
	t.Run("blank table name", func(t *testing.T) {
		assert := assert.New(t)
		ok, _ := w.hasTable(testCtx, "")
		assert.Equal(ok, false)
	})
}

// TestWriter_createTableLike provides unit tests for Writer createTable
func TestWriter_createTableLike(t *testing.T) {
	testCtx := context.Background()
	db, _ := setup(testCtx, t)
	t.Run("success", func(t *testing.T) {
		assert := assert.New(t)
		w := Writer{db}
		suffix := testId(t)
		u := &oplog_test.TestUser{}
		newTableName := u.TableName() + "_" + suffix
		defer func() { assert.NoError(w.dropTableIfExists(testCtx, newTableName)) }()
		err := w.createTableLike(testCtx, u.TableName(), newTableName)
		assert.NoError(err)
	})
	t.Run("call twice", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		w := Writer{db}
		suffix := testId(t)
		u := &oplog_test.TestUser{}
		newTableName := u.TableName() + "_" + suffix
		defer func() { assert.NoError(w.dropTableIfExists(testCtx, newTableName)) }()
		err := w.createTableLike(testCtx, u.TableName(), newTableName)
		require.NoError(err)

		// should be an error to create the same table twice
		err = w.createTableLike(testCtx, u.TableName(), newTableName)
		require.Error(err)
		assert.Error(err, err.Error(), nil)
	})
	t.Run("empty existing", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		w := Writer{db}
		suffix := testId(t)
		u := &oplog_test.TestUser{}
		newTableName := u.TableName() + "_" + suffix
		defer func() { assert.NoError(w.dropTableIfExists(testCtx, newTableName)) }()
		err := w.createTableLike(testCtx, "", newTableName)
		require.Error(err)
		assert.Error(err, err.Error(), nil)
		assert.Contains(err.Error(), "missing existing table name")
	})
	t.Run("blank name", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		w := Writer{db}
		u := &oplog_test.TestUser{}
		err := w.createTableLike(testCtx, u.TableName(), "")
		require.Error(err)
		assert.Error(err, err.Error(), nil)
		assert.Contains(err.Error(), "missing new table name")
	})
}

// Test_WriterDropTableIfExists provides unit tests for Writer dropTableIfExists
func Test_WriterDropTableIfExists(t *testing.T) {
	testCtx := context.Background()
	db, _ := setup(testCtx, t)
	t.Run("success", func(t *testing.T) {
		assert := assert.New(t)
		w := Writer{db}
		suffix := testId(t)

		u := &oplog_test.TestUser{}
		newTableName := u.TableName() + "_" + suffix

		assert.NoError(w.createTableLike(testCtx, u.TableName(), newTableName))
		defer func() { assert.NoError(w.dropTableIfExists(testCtx, newTableName)) }()
	})

	t.Run("success with blank", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		w := Writer{db}
		err := w.dropTableIfExists(testCtx, "")
		require.Error(err)
		assert.Contains(err.Error(), "missing table name")
	})
}

func TestWriter_Update(t *testing.T) {
	db, _ := setup(context.Background(), t)
	id := testId(t)
	type args struct {
		user           *oplog_test.TestUser
		fieldMaskPaths []string
		setToNullPaths []string
	}
	tests := []struct {
		name     string
		Tx       *dbw.DB
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
				Version:     2,
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
				Version:     2,
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
				Version:     2,
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
			underlyingDB, err := db.SqlDB(context.Background())
			require.NoError(err)
			_, name, err := db.DbType()
			require.NoError(err)
			dbassert := dbassert.New(t, underlyingDB, name)

			w := &Writer{
				tt.Tx,
			}
			u := testUser(t, db, tt.name+id, id, id) // intentionally, not relying on tt.Tx
			u.Name = tt.args.user.Name
			u.Email = tt.args.user.Email
			u.PhoneNumber = tt.args.user.PhoneNumber
			_, err = dbw.New(w.DB).Update(context.Background(), u, tt.args.fieldMaskPaths, tt.args.setToNullPaths)
			if tt.wantErr {
				require.Error(err)
				return
			}
			require.NoError(err)
			var foundUser oplog_test.TestUser
			foundUser.Id = u.Id
			require.NoError(dbw.New(db).LookupBy(context.Background(), &foundUser))
			tt.wantUser.Id = u.Id
			assert.Equal(tt.wantUser, &foundUser)
			for _, f := range tt.args.setToNullPaths {
				dbassert.IsNull(u, f)
			}
		})
	}
	t.Run("nil model", func(t *testing.T) {
		assert := assert.New(t)
		w := Writer{db}
		err := dbw.New(w.DB).Create(context.Background(), nil)
		assert.Error(err)
	})
}
