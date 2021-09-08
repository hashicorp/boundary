package oplog

import (
	"context"
	"fmt"
	"testing"

	dbassert "github.com/hashicorp/dbassert/gorm"

	"github.com/hashicorp/boundary/internal/oplog/oplog_test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
)

// setup the tests (initialize the database one-time and intialized testDatabaseURL)
func setup(t *testing.T) (func() error, *gorm.DB) {
	t.Helper()
	require := require.New(t)
	cleanup, url, err := testInitDbInDocker(t)
	require.NoError(err)
	db, err := testOpen("postgres", url)
	require.NoError(err)
	oplog_test.Init(db)
	t.Cleanup(func() {
		sqlDB, err := db.DB()
		assert.NoError(t, err)
		assert.NoError(t, sqlDB.Close(), "Got error closing gorm db.")
	})
	require.NoError(err)
	oplog_test.Init(db)
	return cleanup, db
}

func testOpen(dbType string, connectionUrl string) (*gorm.DB, error) {
	var dialect gorm.Dialector
	switch dbType {
	case "postgres":
		dialect = postgres.New(postgres.Config{
			DSN: connectionUrl},
		)
	default:
		return nil, fmt.Errorf("unable to open %s database type", dbType)
	}
	db, err := gorm.Open(dialect, &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("unable to open database: %w", err)
	}
	return db, nil
}

// Test_BasicOplog provides some basic unit tests for oplogs
func Test_BasicOplog(t *testing.T) {
	cleanup, db := setup(t)
	defer testCleanup(t, cleanup, db)

	t.Run("EncryptData/DecryptData/UnmarshalData", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		cipherer := testWrapper(t)

		// now let's us optimistic locking via a ticketing system for a serialized oplog
		ticketer, err := NewGormTicketer(db, WithAggregateNames(true))
		require.NoError(err)

		types, err := NewTypeCatalog(Type{new(oplog_test.TestUser), "user"})
		require.NoError(err)
		queue := Queue{Catalog: types}

		id := testId(t)
		user := testUser(t, db, "foo-"+id, "", "")

		err = queue.Add(user, "user", OpType_OP_TYPE_CREATE)
		require.NoError(err)
		l, err := NewEntry(
			"test-users",
			Metadata{
				"key-only":   nil,
				"deployment": []string{"amex"},
				"project":    []string{"central-info-systems", "local-info-systems"},
			},
			cipherer,
			ticketer,
		)
		require.NoError(err)
		l.Data = queue.Bytes()

		err = l.EncryptData(context.Background())
		require.NoError(err)

		err = db.Create(&l).Error
		require.NoError(err)
		assert.NotNil(l.CreateTime)
		assert.NotNil(l.UpdateTime)
		entryId := l.Id

		var foundEntry Entry
		err = db.Where("id = ?", entryId).First(&foundEntry).Error
		require.NoError(err)
		foundEntry.Cipherer = cipherer
		err = foundEntry.DecryptData(context.Background())
		require.NoError(err)

		foundUsers, err := foundEntry.UnmarshalData(types)
		require.NoError(err)
		assert.Equal(foundUsers[0].Message.(*oplog_test.TestUser).Name, user.Name)
		foundUsers, err = foundEntry.UnmarshalData(types)
		require.NoError(err)
		assert.Equal(foundUsers[0].Message.(*oplog_test.TestUser).Name, user.Name)
	})

	t.Run("write entry", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		cipherer := testWrapper(t)

		// now let's us optimistic locking via a ticketing system for a serialized oplog
		ticketer, err := NewGormTicketer(db, WithAggregateNames(true))
		require.NoError(err)

		types, err := NewTypeCatalog(Type{new(oplog_test.TestUser), "user"})
		require.NoError(err)

		queue := Queue{Catalog: types}

		id := testId(t)
		user := testUser(t, db, "foo-"+id, "", "")

		ticket, err := ticketer.GetTicket("default")
		require.NoError(err)

		queue = Queue{}
		err = queue.Add(user, "user", OpType_OP_TYPE_CREATE)
		require.NoError(err)

		newLogEntry, err := NewEntry(
			"test-users",
			Metadata{
				"key-only":   nil,
				"deployment": []string{"amex"},
				"project":    []string{"central-info-systems", "local-info-systems"},
			},
			cipherer,
			ticketer,
		)
		require.NoError(err)
		newLogEntry.Data = queue.Bytes()
		err = newLogEntry.Write(context.Background(), &GormWriter{db}, ticket)
		require.NoError(err)
		assert.NotEmpty(newLogEntry.Id)
	})
}

// Test_NewEntry provides some basic unit tests for NewEntry
func Test_NewEntry(t *testing.T) {
	cleanup, db := setup(t)
	defer testCleanup(t, cleanup, db)

	t.Run("valid", func(t *testing.T) {
		require := require.New(t)
		cipherer := testWrapper(t)
		ticketer, err := NewGormTicketer(db, WithAggregateNames(true))
		require.NoError(err)

		_, err = NewEntry(
			"test-users",
			Metadata{
				"key-only":   nil,
				"deployment": []string{"amex"},
				"project":    []string{"central-info-systems", "local-info-systems"},
			},
			cipherer,
			ticketer,
		)
		require.NoError(err)
	})
	t.Run("no metadata success", func(t *testing.T) {
		require := require.New(t)
		cipherer := testWrapper(t)
		ticketer, err := NewGormTicketer(db, WithAggregateNames(true))
		require.NoError(err)

		_, err = NewEntry(
			"test-users",
			nil,
			cipherer,
			ticketer,
		)
		require.NoError(err)
	})
	t.Run("no aggregateName", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		cipherer := testWrapper(t)
		ticketer, err := NewGormTicketer(db, WithAggregateNames(true))
		require.NoError(err)

		_, err = NewEntry(
			"",
			Metadata{
				"key-only":   nil,
				"deployment": []string{"amex"},
				"project":    []string{"central-info-systems", "local-info-systems"},
			},
			cipherer,
			ticketer,
		)
		require.Error(err)
		assert.Equal("oplog.NewEntry: oplog.(Entry).validate: missing entry aggregate name: parameter violation: error #100", err.Error())
	})
	t.Run("bad cipherer", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		ticketer, err := NewGormTicketer(db, WithAggregateNames(true))
		require.NoError(err)

		_, err = NewEntry(
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
		assert.Equal("oplog.NewEntry: oplog.(Entry).validate: nil cipherer: parameter violation: error #100", err.Error())
	})
	t.Run("bad ticket", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		cipherer := testWrapper(t)
		_, err := NewEntry(
			"test-users",
			Metadata{
				"key-only":   nil,
				"deployment": []string{"amex"},
				"project":    []string{"central-info-systems", "local-info-systems"},
			},
			cipherer,
			nil,
		)
		require.Error(err)
		assert.Equal("oplog.NewEntry: oplog.(Entry).validate: nil ticketer: parameter violation: error #100", err.Error())
	})
}

func Test_UnmarshalData(t *testing.T) {
	cleanup, db := setup(t)
	defer testCleanup(t, cleanup, db)

	cipherer := testWrapper(t)

	// now let's us optimistic locking via a ticketing system for a serialized oplog
	ticketer, err := NewGormTicketer(db, WithAggregateNames(true))

	types, err := NewTypeCatalog(Type{new(oplog_test.TestUser), "user"})
	require.NoError(t, err)

	id := testId(t)

	t.Run("valid", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		queue := Queue{Catalog: types}

		user := oplog_test.TestUser{
			Name: "foo-" + id,
		}
		err = queue.Add(&user, "user", OpType_OP_TYPE_CREATE)
		require.NoError(err)
		entry, err := NewEntry(
			"test-users",
			Metadata{
				"key-only":   nil,
				"deployment": []string{"amex"},
				"project":    []string{"central-info-systems", "local-info-systems"},
			},
			cipherer,
			ticketer,
		)
		require.NoError(err)
		entry.Data = queue.Bytes()
		marshaledUsers, err := entry.UnmarshalData(types)
		require.NoError(err)
		assert.Equal(marshaledUsers[0].Message.(*oplog_test.TestUser).Name, user.Name)

		take2marshaledUsers, err := entry.UnmarshalData(types)
		require.NoError(err)
		assert.Equal(take2marshaledUsers[0].Message.(*oplog_test.TestUser).Name, user.Name)
	})

	t.Run("no data", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		queue := Queue{Catalog: types}
		entry, err := NewEntry(
			"test-users",
			Metadata{
				"key-only":   nil,
				"deployment": []string{"amex"},
				"project":    []string{"central-info-systems", "local-info-systems"},
			},
			cipherer,
			ticketer,
		)
		require.NoError(err)
		entry.Data = queue.Bytes()
		_, err = entry.UnmarshalData(types)
		require.Error(err)
		assert.Equal("oplog.(Entry).UnmarshalData: missing data: parameter violation: error #100", err.Error())
	})

	t.Run("nil types", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		queue := Queue{Catalog: types}

		user := oplog_test.TestUser{
			Name: "foo-" + id,
		}
		err = queue.Add(&user, "user", OpType_OP_TYPE_CREATE)
		require.NoError(err)
		entry, err := NewEntry(
			"test-users",
			Metadata{
				"key-only":   nil,
				"deployment": []string{"amex"},
				"project":    []string{"central-info-systems", "local-info-systems"},
			},
			cipherer,
			ticketer,
		)
		require.NoError(err)
		_, err = entry.UnmarshalData(nil)
		require.Error(err)
		assert.Equal("oplog.(Entry).UnmarshalData: nil type catalog: parameter violation: error #100", err.Error())
	})

	t.Run("missing type", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		queue := Queue{Catalog: types}

		user := oplog_test.TestUser{
			Name: "foo-" + id,
		}
		err = queue.Add(&user, "user", OpType_OP_TYPE_CREATE)
		require.NoError(err)
		entry, err := NewEntry(
			"test-users",
			Metadata{
				"key-only":   nil,
				"deployment": []string{"amex"},
				"project":    []string{"central-info-systems", "local-info-systems"},
			},
			cipherer,
			ticketer,
		)
		require.NoError(err)
		entry.Data = queue.Bytes()
		types, err := NewTypeCatalog(Type{new(oplog_test.TestUser), "not-valid-name"})
		require.NoError(err)
		_, err = entry.UnmarshalData(types)
		require.Error(err)
		assert.Equal("oplog.(Entry).UnmarshalData: error removing item from queue: oplog.(Queue).Remove: error getting the TypeName: user: oplog.(TypeCatalog).Get: type name not found: integrity violation: error #105", err.Error())
	})
}

// Test_Replay provides some basic unit tests for replaying entries
func Test_Replay(t *testing.T) {
	cleanup, db := setup(t)
	defer testCleanup(t, cleanup, db)

	cipherer := testWrapper(t)
	id := testId(t)

	// setup new tables for replay
	tableSuffix := "_" + id
	writer := GormWriter{Tx: db}

	userModel := &oplog_test.TestUser{}
	replayUserTable := fmt.Sprintf("%s%s", userModel.TableName(), tableSuffix)
	defer func() { require.NoError(t, writer.dropTableIfExists(replayUserTable)) }()

	ticketer, err := NewGormTicketer(db, WithAggregateNames(true))
	require.NoError(t, err)

	t.Run("replay:create/update", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		ticket, err := ticketer.GetTicket("default")
		require.NoError(err)

		newLogEntry, err := NewEntry(
			"test-users",
			Metadata{
				"key-only":   nil,
				"deployment": []string{"amex"},
				"project":    []string{"central-info-systems", "local-info-systems"},
			},
			cipherer,
			ticketer,
		)
		require.NoError(err)

		tx := db
		loginName := "foo-" + testId(t)
		userCreate := testUser(t, db, loginName, "", "")
		userSave := oplog_test.TestUser{
			Id:    userCreate.Id,
			Name:  userCreate.Name,
			Email: loginName + "@hashicorp.com",
		}
		err = tx.Save(&userSave).Error
		require.NoError(err)

		userUpdate := oplog_test.TestUser{
			Id: userCreate.Id,
		}
		err = tx.Model(&userUpdate).Updates(map[string]interface{}{"PhoneNumber": "867-5309", "Name": gorm.Expr("NULL")}).Error
		require.NoError(err)
		underlyingDB, err := tx.DB()
		require.NoError(err)
		dbassert := dbassert.New(t, underlyingDB, tx.Dialector.Name())
		dbassert.IsNull(&userUpdate, "Name")

		foundCreateUser := testFindUser(t, tx, userCreate.Id)
		require.Equal(foundCreateUser.Id, userCreate.Id)
		require.Equal(foundCreateUser.Name, "")
		require.Equal(foundCreateUser.PhoneNumber, userUpdate.PhoneNumber)

		err = newLogEntry.WriteEntryWith(context.Background(), &GormWriter{tx}, ticket,
			&Message{Message: userCreate, TypeName: "user", OpType: OpType_OP_TYPE_CREATE},
			&Message{Message: &userSave, TypeName: "user", OpType: OpType_OP_TYPE_UPDATE, FieldMaskPaths: []string{"Name", "Email"}},
			&Message{Message: &userSave, TypeName: "user", OpType: OpType_OP_TYPE_UPDATE, FieldMaskPaths: []string{"Name", "Email"}, SetToNullPaths: nil},
			&Message{Message: &userUpdate, TypeName: "user", OpType: OpType_OP_TYPE_UPDATE, SetToNullPaths: []string{"Name"}},
			&Message{Message: &userUpdate, TypeName: "user", OpType: OpType_OP_TYPE_UPDATE, FieldMaskPaths: nil, SetToNullPaths: []string{"Name"}},
			&Message{Message: &userUpdate, TypeName: "user", OpType: OpType_OP_TYPE_UPDATE, FieldMaskPaths: []string{"PhoneNumber"}, SetToNullPaths: []string{"Name"}},
		)
		require.NoError(err)

		types, err := NewTypeCatalog(Type{new(oplog_test.TestUser), "user"})
		require.NoError(err)

		var foundEntry Entry
		err = tx.Where("id = ?", newLogEntry.Id).First(&foundEntry).Error
		require.NoError(err)
		foundEntry.Cipherer = cipherer
		err = foundEntry.DecryptData(context.Background())
		require.NoError(err)

		err = foundEntry.Replay(context.Background(), &GormWriter{tx}, types, tableSuffix)
		require.NoError(err)
		foundUser := testFindUser(t, tx, userCreate.Id)

		var foundReplayedUser oplog_test.TestUser
		foundReplayedUser.Table = foundReplayedUser.TableName() + tableSuffix
		err = tx.Where("id = ?", userCreate.Id).First(&foundReplayedUser).Error
		require.NoError(err)

		assert.Equal(foundUser.Id, foundReplayedUser.Id)
		assert.Equal(foundUser.Name, foundReplayedUser.Name)
		assert.Equal(foundUser.PhoneNumber, foundReplayedUser.PhoneNumber)
		assert.Equal(foundReplayedUser.PhoneNumber, "867-5309")
		assert.Equal(foundUser.Email, foundReplayedUser.Email)
		assert.Equal(foundReplayedUser.Email, loginName+"@hashicorp.com")
	})

	t.Run("replay:delete", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		// we need to test delete replays now...
		tx2 := db.Begin()
		defer tx2.Commit()

		ticket2, err := ticketer.GetTicket("default")
		require.NoError(err)

		id4 := testId(t)
		loginName2 := "foo-" + id4
		// create a user that's replayable
		userCreate2 := oplog_test.TestUser{
			Name: loginName2,
		}
		err = tx2.Create(&userCreate2).Error
		require.NoError(err)

		deleteUser2 := oplog_test.TestUser{
			Id: userCreate2.Id,
		}
		err = tx2.Delete(&deleteUser2).Error
		require.NoError(err)

		newLogEntry2, err := NewEntry(
			"test-users",
			Metadata{
				"key-only":   nil,
				"deployment": []string{"amex"},
				"project":    []string{"central-info-systems", "local-info-systems"},
			},
			cipherer,
			ticketer,
		)
		require.NoError(err)
		err = newLogEntry2.WriteEntryWith(context.Background(), &GormWriter{tx2}, ticket2,
			&Message{Message: &userCreate2, TypeName: "user", OpType: OpType_OP_TYPE_CREATE},
			&Message{Message: &deleteUser2, TypeName: "user", OpType: OpType_OP_TYPE_DELETE},
		)
		require.NoError(err)

		var foundEntry2 Entry
		err = tx2.Where("id = ?", newLogEntry2.Id).First(&foundEntry2).Error
		require.NoError(err)
		foundEntry2.Cipherer = cipherer
		err = foundEntry2.DecryptData(context.Background())
		require.NoError(err)

		types, err := NewTypeCatalog(Type{new(oplog_test.TestUser), "user"})
		require.NoError(err)

		err = foundEntry2.Replay(context.Background(), &GormWriter{tx2}, types, tableSuffix)
		require.NoError(err)

		var foundUser2 oplog_test.TestUser
		err = tx2.Where("id = ?", userCreate2.Id).First(&foundUser2).Error
		assert.Equal(gorm.ErrRecordNotFound, err, err.Error())

		var foundReplayedUser2 oplog_test.TestUser
		err = tx2.Where("id = ?", userCreate2.Id).First(&foundReplayedUser2).Error
		assert.Equal(gorm.ErrRecordNotFound, err, err.Error())
	})
}

// Test_WriteEntryWith provides unit tests for oplog.WriteEntryWith
func Test_WriteEntryWith(t *testing.T) {
	cleanup, db := setup(t)
	defer testCleanup(t, cleanup, db)
	cipherer := testWrapper(t)

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

	ticketer, err := NewGormTicketer(db, WithAggregateNames(true))
	require.NoError(t, err)

	ticket, err := ticketer.GetTicket("default")
	require.NoError(t, err)

	t.Run("successful", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		newLogEntry, err := NewEntry(
			"test-users",
			Metadata{
				"key-only":   nil,
				"deployment": []string{"amex"},
				"project":    []string{"central-info-systems", "local-info-systems"},
			},
			cipherer,
			ticketer,
		)
		require.NoError(err)
		err = newLogEntry.WriteEntryWith(context.Background(), &GormWriter{db}, ticket,
			&Message{Message: &u, TypeName: "user", OpType: OpType_OP_TYPE_CREATE},
			&Message{Message: &u2, TypeName: "user", OpType: OpType_OP_TYPE_CREATE})
		require.NoError(err)

		var foundEntry Entry
		err = db.Where("id = ?", newLogEntry.Id).First(&foundEntry).Error
		require.NoError(err)
		foundEntry.Cipherer = cipherer
		types, err := NewTypeCatalog(Type{new(oplog_test.TestUser), "user"})
		require.NoError(err)
		err = foundEntry.DecryptData(context.Background())
		require.NoError(err)
		foundUsers, err := foundEntry.UnmarshalData(types)
		require.NoError(err)
		assert.Equal(foundUsers[0].Message.(*oplog_test.TestUser).Name, u.Name)
	})
	t.Run("nil writer", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		newLogEntry, err := NewEntry(
			"test-users",
			Metadata{
				"key-only":   nil,
				"deployment": []string{"amex"},
				"project":    []string{"central-info-systems", "local-info-systems"},
			},
			cipherer,
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
			"test-users",
			Metadata{
				"key-only":   nil,
				"deployment": []string{"amex"},
				"project":    []string{"central-info-systems", "local-info-systems"},
			},
			cipherer,
			ticketer,
		)
		require.NoError(err)
		err = newLogEntry.WriteEntryWith(context.Background(), &GormWriter{db}, nil,
			&Message{Message: &u, TypeName: "user", OpType: OpType_OP_TYPE_CREATE},
			&Message{Message: &u2, TypeName: "user", OpType: OpType_OP_TYPE_CREATE})
		require.Error(err)
		assert.Equal("oplog.(Entry).WriteEntryWith: nil ticket: parameter violation: error #100", err.Error())
	})
	t.Run("nil ticket", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		newLogEntry, err := NewEntry(
			"test-users",
			Metadata{
				"key-only":   nil,
				"deployment": []string{"amex"},
				"project":    []string{"central-info-systems", "local-info-systems"},
			},
			cipherer,
			ticketer,
		)
		require.NoError(err)
		err = newLogEntry.WriteEntryWith(context.Background(), &GormWriter{db}, ticket, nil)
		require.Error(err)
		assert.Equal("oplog.(Entry).WriteEntryWith: nil message: parameter violation: error #100", err.Error())
	})
}

// Test_TicketSerialization provides unit tests for making sure oplog.Tickets properly serialize writes to oplog entries
func Test_TicketSerialization(t *testing.T) {
	cleanup, db := setup(t)
	defer testCleanup(t, cleanup, db)
	assert, require := assert.New(t), require.New(t)

	ticketer, err := NewGormTicketer(db, WithAggregateNames(true))
	require.NoError(err)

	cipherer := testWrapper(t)

	id := testId(t)
	firstTx := db.Begin()
	firstUser := oplog_test.TestUser{
		Name: "foo-" + id,
	}
	err = firstTx.Create(&firstUser).Error
	require.NoError(err)
	firstTicket, err := ticketer.GetTicket("default")
	require.NoError(err)

	firstQueue := Queue{}
	err = firstQueue.Add(&firstUser, "user", OpType_OP_TYPE_CREATE)
	require.NoError(err)

	firstLogEntry, err := NewEntry(
		"test-users",
		Metadata{
			"key-only":   nil,
			"deployment": []string{"amex"},
			"project":    []string{"central-info-systems", "local-info-systems"},
		},
		cipherer,
		ticketer,
	)
	require.NoError(err)

	firstLogEntry.Data = firstQueue.Bytes()
	id2 := testId(t)
	secondTx := db.Begin()
	secondUser := oplog_test.TestUser{
		Name: "foo-" + id2,
	}
	err = secondTx.Create(&secondUser).Error
	require.NoError(err)
	secondTicket, err := ticketer.GetTicket("default")
	require.NoError(err)

	secondQueue := Queue{}
	err = secondQueue.Add(&secondUser, "user", OpType_OP_TYPE_CREATE)
	require.NoError(err)

	secondLogEntry, err := NewEntry(
		"foobar",
		Metadata{
			"key-only":   nil,
			"deployment": []string{"amex"},
			"project":    []string{"central-info-systems", "local-info-systems"},
		},
		cipherer,
		ticketer,
	)
	require.NoError(err)
	secondLogEntry.Data = secondQueue.Bytes()

	err = secondLogEntry.Write(context.Background(), &GormWriter{secondTx}, secondTicket)
	require.NoError(err)
	assert.NotEmpty(secondLogEntry.Id, 0)
	assert.NotNil(secondLogEntry.CreateTime)
	assert.NotNil(secondLogEntry.UpdateTime)
	err = secondTx.Commit().Error
	require.NoError(err)
	assert.NotNil(secondLogEntry.Id)

	err = firstLogEntry.Write(context.Background(), &GormWriter{firstTx}, firstTicket)
	if err != nil {
		firstTx.Rollback()
	} else {
		firstTx.Commit()
		t.Error("should have failed to write firstLogEntry")
	}
}
