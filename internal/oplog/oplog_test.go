// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package oplog

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/internal/oplog/oplog_test"
	dbassert "github.com/hashicorp/dbassert/gorm"
	"github.com/hashicorp/go-dbw"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
)

// Test_BasicOplog provides some basic unit tests for oplogs
func Test_BasicOplog(t *testing.T) {
	testCtx := context.Background()
	db, wrapper := setup(testCtx, t)

	t.Run("EncryptData/DecryptData/UnmarshalData", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		keyId, err := wrapper.KeyId(testCtx)
		require.NoError(err)

		// now let's us optimistic locking via a ticketing system for a serialized oplog
		ticketer, err := NewTicketer(testCtx, db, WithAggregateNames(true))
		require.NoError(err)

		types, err := NewTypeCatalog(testCtx, Type{new(oplog_test.TestUser), "user"})
		require.NoError(err)
		queue := Queue{Catalog: types}

		id := testId(t)
		user := testUser(t, db, "foo-"+id, "", "")

		err = queue.add(testCtx, user, "user", OpType_OP_TYPE_CREATE)
		require.NoError(err)
		l, err := NewEntry(
			testCtx,
			"test-users",
			Metadata{
				"key-only":   nil,
				"deployment": []string{"amex"},
				"project":    []string{"central-info-systems", "local-info-systems"},
			},
			wrapper,
			ticketer,
		)
		require.NoError(err)
		l.Data = queue.Bytes()

		err = l.encryptData(context.Background())
		require.NoError(err)

		err = dbw.New(db).Create(testCtx, &l)
		require.NoError(err)
		assert.NotNil(l.CreateTime)
		assert.NotNil(l.UpdateTime)
		entryId := l.Id

		var foundEntry Entry
		err = dbw.New(db).LookupWhere(testCtx, &foundEntry, "id = ?", []any{entryId})
		require.NoError(err)
		foundEntry.Wrapper = wrapper
		err = foundEntry.DecryptData(context.Background())
		require.NoError(err)
		require.Equal(keyId, foundEntry.KeyId)
		require.Equal("global", foundEntry.ScopeId)

		foundUsers, err := foundEntry.UnmarshalData(testCtx, types)
		require.NoError(err)
		assert.Equal(foundUsers[0].Message.(*oplog_test.TestUser).Name, user.Name)
		foundUsers, err = foundEntry.UnmarshalData(testCtx, types)
		require.NoError(err)
		assert.Equal(foundUsers[0].Message.(*oplog_test.TestUser).Name, user.Name)
	})

	t.Run("write entry", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		// now let's us optimistic locking via a ticketing system for a serialized oplog
		ticketer, err := NewTicketer(testCtx, db, WithAggregateNames(true))
		require.NoError(err)

		types, err := NewTypeCatalog(testCtx, Type{new(oplog_test.TestUser), "user"})
		require.NoError(err)

		queue := Queue{Catalog: types}

		id := testId(t)
		user := testUser(t, db, "foo-"+id, "", "")
		ticket, err := ticketer.GetTicket(testCtx, "default")
		require.NoError(err)

		err = queue.add(testCtx, user, "user", OpType_OP_TYPE_CREATE)
		require.NoError(err)

		newLogEntry, err := NewEntry(
			testCtx,
			"test-users",
			Metadata{
				"key-only":   nil,
				"deployment": []string{"amex"},
				"project":    []string{"central-info-systems", "local-info-systems"},
			},
			wrapper,
			ticketer,
		)
		require.NoError(err)
		newLogEntry.Data = queue.Bytes()
		err = newLogEntry.Write(context.Background(), &Writer{db}, ticket)
		require.NoError(err)
		assert.NotEmpty(newLogEntry.Id)
	})
}

// Test_NewEntry provides some basic unit tests for NewEntry
func Test_NewEntry(t *testing.T) {
	testCtx := context.Background()
	db, wrapper := setup(testCtx, t)

	t.Run("valid", func(t *testing.T) {
		require := require.New(t)
		ticketer, err := NewTicketer(testCtx, db, WithAggregateNames(true))
		require.NoError(err)
		keyId, err := wrapper.KeyId(testCtx)
		require.NoError(err)

		entry, err := NewEntry(
			testCtx,
			"test-users",
			Metadata{
				"key-only":   nil,
				"deployment": []string{"amex"},
				"project":    []string{"central-info-systems", "local-info-systems"},
			},
			wrapper,
			ticketer,
		)
		require.NoError(err)
		require.Equal(keyId, entry.KeyId)
	})
	t.Run("no metadata success", func(t *testing.T) {
		require := require.New(t)
		ticketer, err := NewTicketer(testCtx, db, WithAggregateNames(true))
		require.NoError(err)

		_, err = NewEntry(
			testCtx,
			"test-users",
			nil,
			wrapper,
			ticketer,
		)
		require.NoError(err)
	})
	t.Run("no aggregateName", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		ticketer, err := NewTicketer(testCtx, db, WithAggregateNames(true))
		require.NoError(err)

		_, err = NewEntry(
			testCtx,
			"",
			Metadata{
				"key-only":   nil,
				"deployment": []string{"amex"},
				"project":    []string{"central-info-systems", "local-info-systems"},
			},
			wrapper,
			ticketer,
		)
		require.Error(err)
		assert.Equal("oplog.NewEntry: oplog.(Entry).validate: missing entry aggregate name: parameter violation: error #100", err.Error())
	})
	t.Run("bad wrapper", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		ticketer, err := NewTicketer(testCtx, db, WithAggregateNames(true))
		require.NoError(err)

		_, err = NewEntry(
			testCtx,
			"test-users",
			Metadata{
				"key-only":   nil,
				"deployment": []string{"amex"},
				"project":    []string{"central-info-systems", "local-info-systems"},
			},
			nil,
			ticketer,
		)
		require.Error(err)
		assert.Equal("oplog.NewEntry: nil wrapper: parameter violation: error #100", err.Error())
	})
	t.Run("bad ticket", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		_, err := NewEntry(
			testCtx,
			"test-users",
			Metadata{
				"key-only":   nil,
				"deployment": []string{"amex"},
				"project":    []string{"central-info-systems", "local-info-systems"},
			},
			wrapper,
			nil,
		)
		require.Error(err)
		assert.Equal("oplog.NewEntry: oplog.(Entry).validate: nil ticketer: parameter violation: error #100", err.Error())
	})
}

func Test_UnmarshalData(t *testing.T) {
	testCtx := context.Background()
	db, wrapper := setup(testCtx, t)

	// now let's us optimistic locking via a ticketing system for a serialized oplog
	ticketer, err := NewTicketer(testCtx, db, WithAggregateNames(true))
	require.NoError(t, err)

	types, err := NewTypeCatalog(testCtx, Type{new(oplog_test.TestUser), "user"})
	require.NoError(t, err)

	id := testId(t)

	t.Run("valid", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		queue := Queue{Catalog: types}

		user := oplog_test.TestUser{
			Name: "foo-" + id,
		}
		err = queue.add(testCtx, &user, "user", OpType_OP_TYPE_CREATE)
		require.NoError(err)
		entry, err := NewEntry(
			testCtx,
			"test-users",
			Metadata{
				"key-only":   nil,
				"deployment": []string{"amex"},
				"project":    []string{"central-info-systems", "local-info-systems"},
			},
			wrapper,
			ticketer,
		)
		require.NoError(err)
		entry.Data = queue.Bytes()
		marshaledUsers, err := entry.UnmarshalData(testCtx, types)
		require.NoError(err)
		assert.Equal(marshaledUsers[0].Message.(*oplog_test.TestUser).Name, user.Name)

		take2marshaledUsers, err := entry.UnmarshalData(testCtx, types)
		require.NoError(err)
		assert.Equal(take2marshaledUsers[0].Message.(*oplog_test.TestUser).Name, user.Name)
	})

	t.Run("no data", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		queue := Queue{Catalog: types}
		entry, err := NewEntry(
			testCtx,
			"test-users",
			Metadata{
				"key-only":   nil,
				"deployment": []string{"amex"},
				"project":    []string{"central-info-systems", "local-info-systems"},
			},
			wrapper,
			ticketer,
		)
		require.NoError(err)
		entry.Data = queue.Bytes()
		_, err = entry.UnmarshalData(testCtx, types)
		require.Error(err)
		assert.Equal("oplog.(Entry).UnmarshalData: missing data: parameter violation: error #100", err.Error())
	})

	t.Run("nil types", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		queue := Queue{Catalog: types}

		user := oplog_test.TestUser{
			Name: "foo-" + id,
		}
		err = queue.add(testCtx, &user, "user", OpType_OP_TYPE_CREATE)
		require.NoError(err)
		entry, err := NewEntry(
			testCtx,
			"test-users",
			Metadata{
				"key-only":   nil,
				"deployment": []string{"amex"},
				"project":    []string{"central-info-systems", "local-info-systems"},
			},
			wrapper,
			ticketer,
		)
		require.NoError(err)
		_, err = entry.UnmarshalData(testCtx, nil)
		require.Error(err)
		assert.Equal("oplog.(Entry).UnmarshalData: nil type catalog: parameter violation: error #100", err.Error())
	})

	t.Run("missing type", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		queue := Queue{Catalog: types}

		user := oplog_test.TestUser{
			Name: "foo-" + id,
		}
		err = queue.add(testCtx, &user, "user", OpType_OP_TYPE_CREATE)
		require.NoError(err)
		entry, err := NewEntry(
			testCtx,
			"test-users",
			Metadata{
				"key-only":   nil,
				"deployment": []string{"amex"},
				"project":    []string{"central-info-systems", "local-info-systems"},
			},
			wrapper,
			ticketer,
		)
		require.NoError(err)
		entry.Data = queue.Bytes()
		types, err := NewTypeCatalog(testCtx, Type{new(oplog_test.TestUser), "not-valid-name"})
		require.NoError(err)
		_, err = entry.UnmarshalData(testCtx, types)
		require.Error(err)
		assert.Equal("oplog.(Entry).UnmarshalData: error removing item from queue: oplog.(Queue).Remove: error getting the TypeName: user: oplog.(TypeCatalog).Get: type name not found: integrity violation: error #105", err.Error())
	})
}

// Test_Replay provides some basic unit tests for replaying entries
func Test_Replay(t *testing.T) {
	testCtx := context.Background()
	db, wrapper := setup(testCtx, t)

	id := testId(t)

	// setup new tables for replay
	tableSuffix := "_" + id
	writer := Writer{db}

	userModel := &oplog_test.TestUser{}
	replayUserTable := fmt.Sprintf("%s%s", userModel.TableName(), tableSuffix)
	defer func() { require.NoError(t, writer.dropTableIfExists(testCtx, replayUserTable)) }()

	ticketer, err := NewTicketer(testCtx, db, WithAggregateNames(true))
	require.NoError(t, err)

	t.Run("replay:create/update/createitems", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		ticket, err := ticketer.GetTicket(testCtx, "default")
		require.NoError(err)

		newLogEntry, err := NewEntry(
			testCtx,
			"test-users",
			Metadata{
				"key-only":   nil,
				"deployment": []string{"amex"},
				"project":    []string{"central-info-systems", "local-info-systems"},
			},
			wrapper,
			ticketer,
		)
		require.NoError(err)

		tx := dbw.New(db)
		loginName := "foo-" + testId(t)
		userCreate := testUser(t, db, loginName, "", "")
		userSave := oplog_test.TestUser{
			Id:    userCreate.Id,
			Name:  userCreate.Name,
			Email: loginName + "@hashicorp.com",
		}
		version := uint32(1)
		rowsUpdated, err := tx.Update(testCtx, &userSave, []string{"Email"}, nil, dbw.WithVersion(&version), dbw.WithWhere("name = ?", loginName))
		require.NoError(err)
		require.Equal(1, rowsUpdated)

		userUpdate := oplog_test.TestUser{
			Id:          userCreate.Id,
			PhoneNumber: "867-5309",
		}

		tx.Update(testCtx, &userUpdate, []string{"PhoneNumber"}, []string{"Name"})
		require.NoError(err)
		underlyingDB, err := tx.DB().SqlDB(testCtx)
		require.NoError(err)
		_, dialectName, err := tx.DB().DbType()
		require.NoError(err)
		dbassert := dbassert.New(t, underlyingDB, dialectName)
		dbassert.IsNull(&userUpdate, "Name")

		foundCreateUser := testFindUser(t, tx.DB(), userCreate.Id)
		require.Equal(foundCreateUser.Id, userCreate.Id)
		require.Equal(foundCreateUser.Name, "")
		require.Equal(foundCreateUser.PhoneNumber, userUpdate.PhoneNumber)

		userCreateItems := &oplog_test.TestUser{
			Name: "foo-" + testId(t),
		}
		require.NoError(dbw.New(db).CreateItems(context.Background(), []*oplog_test.TestUser{userCreateItems}))

		err = newLogEntry.WriteEntryWith(context.Background(), &Writer{tx.DB()}, ticket,
			&Message{Message: userCreate, TypeName: "user", OpType: OpType_OP_TYPE_CREATE},
			&Message{Message: &userSave, TypeName: "user", OpType: OpType_OP_TYPE_UPDATE, FieldMaskPaths: []string{"Email"}, SetToNullPaths: nil, Opts: []dbw.Option{dbw.WithVersion(&version), dbw.WithWhere("name = ?", loginName)}},
			&Message{Message: &userSave, TypeName: "user", OpType: OpType_OP_TYPE_UPDATE, FieldMaskPaths: []string{"Name", "Email"}, SetToNullPaths: nil},
			&Message{Message: &userUpdate, TypeName: "user", OpType: OpType_OP_TYPE_UPDATE, SetToNullPaths: []string{"Name"}},
			&Message{Message: &userUpdate, TypeName: "user", OpType: OpType_OP_TYPE_UPDATE, FieldMaskPaths: nil, SetToNullPaths: []string{"Name"}},
			&Message{Message: &userUpdate, TypeName: "user", OpType: OpType_OP_TYPE_UPDATE, FieldMaskPaths: []string{"PhoneNumber"}, SetToNullPaths: []string{"Name"}},
			&Message{Message: userCreateItems, TypeName: "user", OpType: OpType_OP_TYPE_CREATE_ITEMS},
		)
		require.NoError(err)

		types, err := NewTypeCatalog(testCtx, Type{new(oplog_test.TestUser), "user"})
		require.NoError(err)

		var foundEntry Entry
		require.NoError(tx.LookupWhere(testCtx, &foundEntry, "id = ?", []any{newLogEntry.Id}))
		foundEntry.Wrapper = wrapper
		err = foundEntry.DecryptData(context.Background())
		require.NoError(err)

		err = foundEntry.Replay(context.Background(), &Writer{tx.DB()}, types, tableSuffix)
		require.NoError(err)
		foundUser := testFindUser(t, tx.DB(), userCreate.Id)

		var foundReplayedUser oplog_test.TestUser
		foundReplayedUser.Table = foundReplayedUser.TableName() + tableSuffix
		require.NoError(tx.LookupWhere(testCtx, &foundReplayedUser, "id = ?", []any{userCreate.Id}))
		require.NoError(err)

		assert.Equal(foundUser.Id, foundReplayedUser.Id)
		assert.Equal(foundUser.Name, foundReplayedUser.Name)
		assert.Equal(foundUser.PhoneNumber, foundReplayedUser.PhoneNumber)
		assert.Equal(foundReplayedUser.PhoneNumber, "867-5309")
		assert.Equal(foundUser.Email, foundReplayedUser.Email)
		assert.Equal(foundReplayedUser.Email, loginName+"@hashicorp.com")

		foundReplayedUser.Id = 0
		require.NoError(tx.LookupWhere(testCtx, &foundReplayedUser, "id = ?", []any{userCreateItems.Id}, dbw.WithDebug(true)))
		require.NoError(err)
	})

	t.Run("replay:delete", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		// we need to test delete replays now...
		tx2, err := dbw.New(db).Begin(testCtx)
		require.NoError(err)
		defer tx2.Commit(testCtx)

		ticket2, err := ticketer.GetTicket(testCtx, "default")
		require.NoError(err)

		id4 := testId(t)
		loginName2 := "foo-" + id4
		// create a user that's replayable
		userCreate2 := oplog_test.TestUser{
			Name: loginName2,
		}
		err = tx2.Create(testCtx, &userCreate2)
		require.NoError(err)

		deleteUser2 := oplog_test.TestUser{
			Id: userCreate2.Id,
		}
		_, err = tx2.Delete(testCtx, &deleteUser2)
		require.NoError(err)

		newLogEntry2, err := NewEntry(
			testCtx,
			"test-users",
			Metadata{
				"key-only":   nil,
				"deployment": []string{"amex"},
				"project":    []string{"central-info-systems", "local-info-systems"},
			},
			wrapper,
			ticketer,
		)
		require.NoError(err)
		err = newLogEntry2.WriteEntryWith(context.Background(), &Writer{tx2.DB()}, ticket2,
			&Message{Message: &userCreate2, TypeName: "user", OpType: OpType_OP_TYPE_CREATE},
			&Message{Message: &deleteUser2, TypeName: "user", OpType: OpType_OP_TYPE_DELETE},
		)
		require.NoError(err)

		var foundEntry2 Entry
		err = tx2.LookupWhere(testCtx, &foundEntry2, "id = ?", []any{newLogEntry2.Id})
		require.NoError(err)
		foundEntry2.Wrapper = wrapper
		err = foundEntry2.DecryptData(context.Background())
		require.NoError(err)

		types, err := NewTypeCatalog(testCtx, Type{new(oplog_test.TestUser), "user"})
		require.NoError(err)

		err = foundEntry2.Replay(context.Background(), &Writer{tx2.DB()}, types, tableSuffix)
		require.NoError(err)

		var foundUser2 oplog_test.TestUser
		err = tx2.LookupWhere(testCtx, &foundUser2, "id = ?", []any{userCreate2.Id})
		assert.ErrorIs(err, dbw.ErrRecordNotFound)

		var foundReplayedUser2 oplog_test.TestUser
		err = tx2.LookupWhere(testCtx, &foundReplayedUser2, "id = ?", []any{userCreate2.Id})
		assert.ErrorIs(err, dbw.ErrRecordNotFound)
	})
	t.Run("replay:deleteitems", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		// we need to test delete replays now...
		tx2, err := dbw.New(db).Begin(testCtx)
		require.NoError(err)
		defer tx2.Commit(testCtx)

		ticket2, err := ticketer.GetTicket(testCtx, "default")
		require.NoError(err)

		id4 := testId(t)
		loginName2 := "foo-" + id4
		// create a user that's replayable
		userCreate2 := oplog_test.TestUser{
			Name: loginName2,
		}
		err = tx2.Create(testCtx, &userCreate2)
		require.NoError(err)

		deleteUser2 := oplog_test.TestUser{
			Id: userCreate2.Id,
		}
		_, err = tx2.DeleteItems(testCtx, []*oplog_test.TestUser{&deleteUser2})
		require.NoError(err)

		newLogEntry2, err := NewEntry(
			testCtx,
			"test-users",
			Metadata{
				"key-only":   nil,
				"deployment": []string{"amex"},
				"project":    []string{"central-info-systems", "local-info-systems"},
			},
			wrapper,
			ticketer,
		)
		require.NoError(err)
		err = newLogEntry2.WriteEntryWith(context.Background(), &Writer{tx2.DB()}, ticket2,
			&Message{Message: &userCreate2, TypeName: "user", OpType: OpType_OP_TYPE_CREATE},
			&Message{Message: &deleteUser2, TypeName: "user", OpType: OpType_OP_TYPE_DELETE_ITEMS},
		)
		require.NoError(err)

		var foundEntry2 Entry
		err = tx2.LookupWhere(testCtx, &foundEntry2, "id = ?", []any{newLogEntry2.Id})
		require.NoError(err)
		foundEntry2.Wrapper = wrapper
		err = foundEntry2.DecryptData(context.Background())
		require.NoError(err)

		types, err := NewTypeCatalog(testCtx, Type{new(oplog_test.TestUser), "user"})
		require.NoError(err)

		err = foundEntry2.Replay(context.Background(), &Writer{tx2.DB()}, types, tableSuffix)
		require.NoError(err)

		var foundUser2 oplog_test.TestUser
		err = tx2.LookupWhere(testCtx, &foundUser2, "id = ?", []any{userCreate2.Id})
		assert.ErrorIs(err, dbw.ErrRecordNotFound)

		var foundReplayedUser2 oplog_test.TestUser
		err = tx2.LookupWhere(testCtx, &foundReplayedUser2, "id = ?", []any{userCreate2.Id})
		assert.ErrorIs(err, dbw.ErrRecordNotFound)
	})
}

// Test_WriteEntryWith provides unit tests for oplog.WriteEntryWith
func Test_WriteEntryWith(t *testing.T) {
	testCtx := context.Background()
	db, wrapper := setup(testCtx, t)

	id := testId(t)
	u := oplog_test.TestUser{
		Name: "foo-" + id,
	}
	t.Log(&u)

	id2 := testId(t)
	u2 := oplog_test.TestUser{
		Name: "foo-" + id2,
	}
	t.Log(&u2)

	ticketer, err := NewTicketer(testCtx, db, WithAggregateNames(true))
	require.NoError(t, err)

	ticket, err := ticketer.GetTicket(testCtx, "default")
	require.NoError(t, err)

	t.Run("successful", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		newLogEntry, err := NewEntry(
			testCtx,
			"test-users",
			Metadata{
				"key-only":   nil,
				"deployment": []string{"amex"},
				"project":    []string{"central-info-systems", "local-info-systems"},
			},
			wrapper,
			ticketer,
		)
		require.NoError(err)
		err = newLogEntry.WriteEntryWith(context.Background(), &Writer{db}, ticket,
			&Message{Message: &u, TypeName: "user", OpType: OpType_OP_TYPE_CREATE},
			&Message{Message: &u2, TypeName: "user", OpType: OpType_OP_TYPE_CREATE})
		require.NoError(err)

		var foundEntry Entry
		require.NoError(dbw.New(db).LookupWhere(testCtx, &foundEntry, "id = ?", []any{newLogEntry.Id}))
		require.NoError(err)
		foundEntry.Wrapper = wrapper
		types, err := NewTypeCatalog(testCtx, Type{new(oplog_test.TestUser), "user"})
		require.NoError(err)
		err = foundEntry.DecryptData(context.Background())
		require.NoError(err)
		foundUsers, err := foundEntry.UnmarshalData(testCtx, types)
		require.NoError(err)
		assert.Equal(foundUsers[0].Message.(*oplog_test.TestUser).Name, u.Name)
	})
	t.Run("nil writer", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		newLogEntry, err := NewEntry(
			testCtx,
			"test-users",
			Metadata{
				"key-only":   nil,
				"deployment": []string{"amex"},
				"project":    []string{"central-info-systems", "local-info-systems"},
			},
			wrapper,
			ticketer,
		)
		require.NoError(err)
		err = newLogEntry.WriteEntryWith(context.Background(), nil, ticket,
			&Message{Message: &u, TypeName: "user", OpType: OpType_OP_TYPE_CREATE},
			&Message{Message: &u2, TypeName: "user", OpType: OpType_OP_TYPE_CREATE})
		require.Error(err)
		assert.Equal("oplog.(Entry).WriteEntryWith: nil writer: parameter violation: error #100", err.Error())
	})
	t.Run("nil ticket", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		newLogEntry, err := NewEntry(
			testCtx,
			"test-users",
			Metadata{
				"key-only":   nil,
				"deployment": []string{"amex"},
				"project":    []string{"central-info-systems", "local-info-systems"},
			},
			wrapper,
			ticketer,
		)
		require.NoError(err)
		err = newLogEntry.WriteEntryWith(context.Background(), &Writer{db}, nil,
			&Message{Message: &u, TypeName: "user", OpType: OpType_OP_TYPE_CREATE},
			&Message{Message: &u2, TypeName: "user", OpType: OpType_OP_TYPE_CREATE})
		require.Error(err)
		assert.Equal("oplog.(Entry).WriteEntryWith: nil ticket: parameter violation: error #100", err.Error())
	})
	t.Run("nil ticket", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		newLogEntry, err := NewEntry(
			testCtx,
			"test-users",
			Metadata{
				"key-only":   nil,
				"deployment": []string{"amex"},
				"project":    []string{"central-info-systems", "local-info-systems"},
			},
			wrapper,
			ticketer,
		)
		require.NoError(err)
		err = newLogEntry.WriteEntryWith(context.Background(), &Writer{db}, ticket, nil)
		require.Error(err)
		assert.Equal("oplog.(Entry).WriteEntryWith: nil message: parameter violation: error #100", err.Error())
	})
}

func TestEntry_WriteEntryWith(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	testCtx := context.Background()
	db, wrapper := setup(testCtx, t)
	db.Debug(true)

	// setup new tables for replay
	id := testId(t)
	tableSuffix := "_" + id

	ticketer, err := NewTicketer(testCtx, db, WithAggregateNames(true))
	require.NoError(err)

	newEntryFn := func() *Entry {
		testEntry, err := NewEntry(
			testCtx,
			"test-users",
			Metadata{
				"key-only":   nil,
				"deployment": []string{"amex"},
				"project":    []string{"central-info-systems", "local-info-systems"},
			},
			wrapper,
			ticketer,
		)
		require.NoError(err)
		return testEntry
	}

	tests := []struct {
		name            string
		e               *Entry
		w               *Writer
		msg             *Message
		wantErr         bool
		wantErrContains string
	}{
		{
			name: "on-conflict-columns-do-nothing",
			e:    newEntryFn(),
			w:    &Writer{db},
			msg: &Message{
				Message:  testUser(t, db, "foo-"+testId(t), "", ""),
				TypeName: "user", OpType: OpType_OP_TYPE_CREATE,
				Opts: []dbw.Option{
					dbw.WithOnConflict(&dbw.OnConflict{
						Target: dbw.Columns{"name"},
						Action: dbw.DoNothing(true),
					}),
				},
			},
		},
		{
			name: "on-conflict-columns-update-all",
			e:    newEntryFn(),
			w:    &Writer{db},
			msg: &Message{
				Message:  testUser(t, db, "foo-"+testId(t), "", ""),
				TypeName: "user", OpType: OpType_OP_TYPE_CREATE,
				Opts: []dbw.Option{
					dbw.WithOnConflict(&dbw.OnConflict{
						Target: dbw.Columns{"name"},
						Action: dbw.UpdateAll(true),
					}),
				},
			},
		},
		{
			name: "on-conflict-columns-set-col-value-with-expr",
			e:    newEntryFn(),
			w:    &Writer{db},
			msg: &Message{
				Message:  testUser(t, db, "foo-"+testId(t), "", ""),
				TypeName: "user", OpType: OpType_OP_TYPE_CREATE,
				Opts: []dbw.Option{
					dbw.WithOnConflict(&dbw.OnConflict{
						Target: dbw.Columns{"name"},
						Action: dbw.SetColumnValues(map[string]any{"name": dbw.Expr("NULL")}),
					}),
				},
			},
		},
		{
			name: "on-conflict-columns-set-col-value",
			e:    newEntryFn(),
			w:    &Writer{db},
			msg: &Message{
				Message:  testUser(t, db, "foo-"+testId(t), "", ""),
				TypeName: "user", OpType: OpType_OP_TYPE_CREATE,
				Opts: []dbw.Option{
					dbw.WithOnConflict(&dbw.OnConflict{
						Target: dbw.Columns{"name"},
						Action: dbw.SetColumnValues(map[string]any{"name": testId(t)}),
					}),
				},
			},
		},
		{
			name: "on-conflict-columns-set-col-value",
			e:    newEntryFn(),
			w:    &Writer{db},
			msg: &Message{
				Message:  testUser(t, db, "foo-"+testId(t), "", ""),
				TypeName: "user", OpType: OpType_OP_TYPE_CREATE,
				Opts: []dbw.Option{
					dbw.WithOnConflict(&dbw.OnConflict{
						Target: dbw.Columns{"name"},
						Action: dbw.SetColumns([]string{"email"}),
					}),
				},
			},
		},
		{
			name: "missing-entry",
			e:    func() *Entry { e := newEntryFn(); e.Entry = nil; return e }(),
			w:    &Writer{db},
			msg: &Message{
				Message:  testUser(t, db, "foo-"+testId(t), "", ""),
				TypeName: "user", OpType: OpType_OP_TYPE_CREATE,
			},
			wantErr:         true,
			wantErrContains: "nil entry",
		},
		{
			name: "missing-entry-version",
			e:    func() *Entry { e := newEntryFn(); e.Entry.Version = ""; return e }(),
			w:    &Writer{db},
			msg: &Message{
				Message:  testUser(t, db, "foo-"+testId(t), "", ""),
				TypeName: "user", OpType: OpType_OP_TYPE_CREATE,
			},
			wantErr:         true,
			wantErrContains: "missing entry version",
		},
		// TODO: jimlambrt (Dec 2021) - we need a way to create a replay table
		// that contains the existing named constraints.  Once that done, we can
		// enable this test and write more.  This is just an example of the type
		// test we need to create using a constraint target
		// {
		// 	name: "on-conflict-column-value",
		// 	e:    testEntry,
		// 	w:    &Writer{db},
		// 	msg: &Message{
		// 		Message:  testUser(t, db, "foo-"+testId(t), "", ""),
		// 		TypeName: "user", OpType: OpType_OP_TYPE_CREATE,
		// 		Opts: []dbw.Option{
		// 			dbw.WithOnConflict(&dbw.OnConflict{
		// 				Target: dbw.Constraint{"oplog_test_user_name_uq"},
		// 				Action: dbw.SetColumnValues(map[string]interface{}{"name": dbw.Expr("NULL")}),
		// 			})},
		// 	},
		// },
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ticket, err := ticketer.GetTicket(testCtx, "default")
			require.NoError(err)
			err = tt.e.WriteEntryWith(
				testCtx,
				tt.w,
				ticket,
				tt.msg,
			)
			if tt.wantErr {
				require.Error(err)
				if tt.wantErrContains != "" {
					assert.Contains(err.Error(), tt.wantErrContains)
				}
				return
			}
			require.NoError(err)
			var foundEntry Entry
			require.NoError(dbw.New(db).LookupWhere(testCtx, &foundEntry, "id = ?", []any{tt.e.Id}))
			require.NoError(err)
			foundEntry.Wrapper = wrapper
			types, err := NewTypeCatalog(testCtx, Type{new(oplog_test.TestUser), "user"})
			require.NoError(err)
			err = foundEntry.DecryptData(context.Background())
			require.NoError(err)
			msgs, err := foundEntry.UnmarshalData(testCtx, types)
			require.NoError(err)
			require.Equal(1, len(msgs))
			entry := msgs[0]
			entryUser := entry.Message.(*oplog_test.TestUser)
			assert.Equal(entryUser.Name, tt.msg.Message.(*oplog_test.TestUser).Name)
			assert.Equal(entry.FieldMaskPaths, tt.msg.FieldMaskPaths)
			assert.Equal(entry.SetToNullPaths, tt.msg.SetToNullPaths)
			assert.Equal(entry.OpType, tt.msg.OpType)
			assert.Equal(entry.TypeName, tt.msg.TypeName)

			entryOpts := dbw.GetOpts(entry.Opts...)
			testMsgOpts := dbw.GetOpts(tt.msg.Opts...)
			assert.Equal(entryOpts, testMsgOpts)

			foundEntry.Wrapper = wrapper
			err = foundEntry.DecryptData(context.Background())
			require.NoError(err)
			err = foundEntry.Replay(context.Background(), tt.w, types, tableSuffix)
			require.NoError(err)
			foundUser := testFindUser(t, tt.w.DB, entryUser.Id)

			var foundReplayedUser oplog_test.TestUser
			foundReplayedUser.Table = foundReplayedUser.TableName() + tableSuffix
			require.NoError(dbw.New(tt.w.DB).LookupWhere(testCtx, &foundReplayedUser, "id = ?", []any{entryUser.Id}))
			require.NoError(err)

			assert.Equal(foundUser.Id, foundReplayedUser.Id)
			assert.Equal(foundUser.Name, foundReplayedUser.Name)
			assert.Equal(foundUser.PhoneNumber, foundReplayedUser.PhoneNumber)
			assert.Equal(foundUser.Email, foundReplayedUser.Email)
		})
	}
}

// Test_TicketSerialization provides unit tests for making sure oplog.Tickets properly serialize writes to oplog entries
func Test_TicketSerialization(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	testCtx := context.Background()
	db, wrapper := setup(testCtx, t)

	ticketer, err := NewTicketer(testCtx, db, WithAggregateNames(true))
	require.NoError(err)

	id := testId(t)
	firstTx, err := dbw.New(db).Begin(testCtx)
	require.NoError(err)
	firstUser := oplog_test.TestUser{
		Name: "foo-" + id,
	}
	err = firstTx.Create(testCtx, &firstUser)
	require.NoError(err)
	firstTicket, err := ticketer.GetTicket(testCtx, "default")
	require.NoError(err)

	firstQueue := Queue{}
	err = firstQueue.add(testCtx, &firstUser, "user", OpType_OP_TYPE_CREATE)
	require.NoError(err)

	firstLogEntry, err := NewEntry(
		testCtx,
		"test-users",
		Metadata{
			"key-only":   nil,
			"deployment": []string{"amex"},
			"project":    []string{"central-info-systems", "local-info-systems"},
		},
		wrapper,
		ticketer,
	)
	require.NoError(err)

	firstLogEntry.Data = firstQueue.Bytes()
	id2 := testId(t)
	secondTx, err := dbw.New(db).Begin(testCtx)
	require.NoError(err)
	secondUser := oplog_test.TestUser{
		Name: "foo-" + id2,
	}
	err = secondTx.Create(testCtx, &secondUser)
	require.NoError(err)
	secondTicket, err := ticketer.GetTicket(testCtx, "default")
	require.NoError(err)

	secondQueue := Queue{}
	err = secondQueue.add(testCtx, &secondUser, "user", OpType_OP_TYPE_CREATE)
	require.NoError(err)

	secondLogEntry, err := NewEntry(
		testCtx,
		"foobar",
		Metadata{
			"key-only":   nil,
			"deployment": []string{"amex"},
			"project":    []string{"central-info-systems", "local-info-systems"},
		},
		wrapper,
		ticketer,
	)
	require.NoError(err)
	secondLogEntry.Data = secondQueue.Bytes()

	err = secondLogEntry.Write(context.Background(), &Writer{secondTx.DB()}, secondTicket)
	require.NoError(err)
	assert.NotEmpty(secondLogEntry.Id, 0)
	assert.NotNil(secondLogEntry.CreateTime)
	assert.NotNil(secondLogEntry.UpdateTime)
	err = secondTx.Commit(testCtx)
	require.NoError(err)
	assert.NotNil(secondLogEntry.Id)

	err = firstLogEntry.Write(context.Background(), &Writer{firstTx.DB()}, firstTicket)
	if err != nil {
		firstTx.Rollback(testCtx)
	} else {
		firstTx.Commit(testCtx)
		t.Error("should have failed to write firstLogEntry")
	}
}
