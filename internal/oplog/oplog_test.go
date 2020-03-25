package oplog

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"

	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/go-kms-wrapping/wrappers/aead"
	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/watchtower/internal/oplog/oplog_test"
	"github.com/jinzhu/gorm"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/matryer/is"
	"github.com/ory/dockertest/v3"
)

// Need a way to manage the shared database resource for these oplog
// tests, so runningTests gives us a waitgroup to do this and clean up
// the shared database resource when we're done.
var runningTests sync.WaitGroup

// startTest signals that we're starting a test that uses the shared test resources
func startTest() {
	runningTests.Add(1)
}

// completeTest signals that we've finished a test that uses the shared test resources
func completeTest() {
	runningTests.Done()
}

// waitForTests will wait for all the tests that are sharing resources like the database
func waitForTests() {
	runningTests.Wait()
}

// testDatabaseURL is initialized once using sync.Once and set to the database URL for testing
var testDatabaseURL string

// testInitDatabase ensures that the database is only initialized once during the tests.
var testInitDatabase sync.Once

// setup the tests (initialize the database one-time and intialized testDatabaseURL)
func setup(t *testing.T) (*is.I, func(), string) {
	cleanup := func() {}
	var url string
	var err error
	testInitDatabase.Do(func() {
		cleanup, url, err = initDbInDocker(t)
		if err != nil {
			panic(err)
		}
		testDatabaseURL = url
		db, err := test_dbconn(url)
		if err != nil {
			panic(err)
		}
		defer db.Close()
		oplog_test.Init(db)
	})
	return is.New(t), cleanup, testDatabaseURL
}

// Test_BasicOplog provides some basic unit tests for oplogs
func Test_BasicOplog(t *testing.T) {
	t.Parallel()
	startTest()
	is, cleanup, url := setup(t)
	defer cleanup()
	defer completeTest() // must come after the "defer cleanup()"
	db, err := test_dbconn(url)
	is.NoErr(err)
	defer db.Close()

	id, err := uuid.GenerateUUID()
	cipherer := initWrapper(t)
	user := oplog_test.TestUser{
		Name: "foo-" + id,
	}

	resp := db.Create(&user)
	is.NoErr(resp.Error)

	// now let's us optimistic locking via a ticketing system for a serialized oplog
	ticketer := &GormTicketer{Tx: db}

	types, err := NewTypeCatalog(Type{new(oplog_test.TestUser), "user"})
	is.NoErr(err)
	queue := Queue{Catalog: types}

	err = queue.Add(&user, "user", OpType_CreateOp)
	is.NoErr(err)
	l, err := NewEntry(
		"test-users",
		Metadata{
			"deployment": "amex",
			"project":    "central-info-systems",
		},
		cipherer,
		ticketer,
	)
	is.NoErr(err)
	l.Data = queue.QueueBuffer

	j, err := json.MarshalIndent(l, "", "    ")
	is.NoErr(err)
	t.Log(string(j))

	err = l.EncryptData(context.Background())
	is.NoErr(err)

	resp = db.Create(&l)
	is.NoErr(resp.Error)
	entryId := l.Id
	j, err = json.MarshalIndent(l, "", "    ")
	is.NoErr(err)
	t.Log(string(j))

	var foundEntry Entry
	err = db.Where("id = ?", entryId).First(&foundEntry).Error
	is.NoErr(err)
	foundEntry.Cipherer = cipherer
	err = foundEntry.DecryptData(context.Background())
	is.NoErr(err)

	foundUsers, err := foundEntry.UnmarshalData(types)
	is.NoErr(err)
	is.True(foundUsers[0].Message.(*oplog_test.TestUser).Name == user.Name)
	t.Log(foundUsers[0])

	ticketName, err := uuid.GenerateUUID()
	is.NoErr(err)
	_, err = ticketer.InitTicket(ticketName)
	is.NoErr(err)
	ticket, err := ticketer.GetTicket(ticketName)
	is.NoErr(err)

	queue = Queue{}
	err = queue.Add(&user, "user", OpType_CreateOp)
	is.NoErr(err)

	newLogEntry, err := NewEntry(
		"test-users",
		Metadata{
			"deployment": "amex",
			"project":    "central-info-systems",
		},
		cipherer,
		ticketer,
	)
	is.NoErr(err)
	newLogEntry.Data = queue.QueueBuffer
	err = newLogEntry.Write(context.Background(), &GormWriter{db}, ticket)
	is.NoErr(err)
	is.True(newLogEntry.Id != 0)
	foundUsers, err = foundEntry.UnmarshalData(types)
	is.NoErr(err)
	is.True(foundUsers[0].Message.(*oplog_test.TestUser).Name == user.Name)
}

// Test_Replay provides some basic unit tests for replaying entries
func Test_Replay(t *testing.T) {
	startTest()
	t.Parallel()
	is, cleanup, url := setup(t)
	defer cleanup()
	defer completeTest() // must come after the "defer cleanup()"
	db, err := test_dbconn(url)
	is.NoErr(err)
	defer db.Close()

	cipherer := initWrapper(t)

	id, err := uuid.GenerateUUID()
	is.NoErr(err)
	// setup new tables for replay
	tableSuffix := "_" + id
	tmpUserModel := &oplog_test.ReplayableTestUser{}
	tmpUserModel.SetTableName(fmt.Sprintf("%s%s", tmpUserModel.TableName(), tableSuffix))
	db.AutoMigrate(tmpUserModel)
	defer db.DropTableIfExists(tmpUserModel)

	ticketName, err := uuid.GenerateUUID()
	is.NoErr(err)
	ticketer := &GormTicketer{Tx: db}

	_, err = ticketer.InitTicket(ticketName)
	is.NoErr(err)
	ticket, err := ticketer.GetTicket(ticketName)
	is.NoErr(err)

	newLogEntry, err := NewEntry(
		"test-users",
		Metadata{
			"deployment": "amex",
			"project":    "central-info-systems",
		},
		cipherer,
		ticketer,
	)
	is.NoErr(err)

	tx := db.Begin()

	id3, err := uuid.GenerateUUID()
	is.NoErr(err)
	userName := "foo-" + id3
	// create a user that's replayable
	userCreate := oplog_test.ReplayableTestUser{
		TestUser: oplog_test.TestUser{
			Name: userName,
		},
	}
	err = tx.Create(&userCreate).Error
	is.NoErr(err)
	userSave := oplog_test.ReplayableTestUser{
		TestUser: oplog_test.TestUser{
			Id:    userCreate.Id,
			Name:  userCreate.Name,
			Email: userName + "@hashicorp.com",
		},
	}
	err = tx.Save(&userSave).Error
	is.NoErr(err)

	userUpdate := oplog_test.ReplayableTestUser{
		TestUser: oplog_test.TestUser{
			Id:          userCreate.Id,
			PhoneNumber: "867-5309",
		},
	}
	err = tx.Model(&userUpdate).Updates(map[string]interface{}{"PhoneNumber": "867-5309"}).Error
	is.NoErr(err)

	err = newLogEntry.WriteEntryWith(context.Background(), &GormWriter{tx}, ticket,
		&Message{Message: &userCreate, TypeURL: "user", OpType: OpType_CreateOp},
		&Message{Message: &userSave, TypeURL: "user", OpType: OpType_UpdateOp},
		&Message{Message: &userUpdate, TypeURL: "user", OpType: OpType_UpdateOp},
	)
	is.NoErr(err)

	types, err := NewTypeCatalog(Type{new(oplog_test.ReplayableTestUser), "user"})
	is.NoErr(err)

	var foundEntry Entry
	err = tx.Where("id = ?", newLogEntry.Id).First(&foundEntry).Error
	is.NoErr(err)
	foundEntry.Cipherer = cipherer
	err = foundEntry.DecryptData(context.Background())
	is.NoErr(err)

	err = foundEntry.Replay(context.Background(), &GormWriter{tx}, types, tableSuffix)
	is.NoErr(err)

	var foundUser oplog_test.TestUser
	err = tx.Where("id = ?", userCreate.Id).First(&foundUser).Error
	is.NoErr(err)

	var foundReplayedUser oplog_test.TestUser
	err = tx.Where("id = ?", userCreate.Id).First(&foundReplayedUser).Error
	is.NoErr(err)

	is.True(foundUser.Id == foundReplayedUser.Id)
	is.True(foundUser.Name == foundReplayedUser.Name && foundUser.Name == userName)
	is.True(foundUser.PhoneNumber == foundReplayedUser.PhoneNumber && foundReplayedUser.PhoneNumber == "867-5309")
	is.True(foundUser.Email == foundReplayedUser.Email && foundReplayedUser.Email == userName+"@hashicorp.com")

	tx.Commit()

	// we need to test delete replays now...
	tx2 := db.Begin()

	ticket2, err := ticketer.GetTicket(ticketName)

	id4, err := uuid.GenerateUUID()
	is.NoErr(err)
	userName2 := "foo-" + id4
	// create a user that's replayable
	userCreate2 := oplog_test.ReplayableTestUser{
		TestUser: oplog_test.TestUser{
			Name: userName2,
		},
	}
	err = tx2.Create(&userCreate2).Error
	is.NoErr(err)

	deleteUser2 := oplog_test.ReplayableTestUser{
		TestUser: oplog_test.TestUser{
			Id: userCreate2.Id,
		},
	}
	err = tx2.Delete(&deleteUser2).Error
	is.NoErr(err)

	newLogEntry2, err := NewEntry(
		"test-users",
		Metadata{
			"deployment": "amex",
			"project":    "central-info-systems",
		},
		cipherer,
		ticketer,
	)
	is.NoErr(err)
	err = newLogEntry2.WriteEntryWith(context.Background(), &GormWriter{tx2}, ticket2,
		&Message{Message: &userCreate2, TypeURL: "user", OpType: OpType_CreateOp},
		&Message{Message: &deleteUser2, TypeURL: "user", OpType: OpType_DeleteOp},
	)
	is.NoErr(err)

	var foundEntry2 Entry
	err = tx2.Where("id = ?", newLogEntry2.Id).First(&foundEntry2).Error
	is.NoErr(err)
	foundEntry2.Cipherer = cipherer
	err = foundEntry2.DecryptData(context.Background())
	is.NoErr(err)

	err = foundEntry2.Replay(context.Background(), &GormWriter{tx2}, types, tableSuffix)
	is.NoErr(err)

	var foundUser2 oplog_test.TestUser
	err = tx2.Where("id = ?", userCreate2.Id).First(&foundUser2).Error
	is.True(err == gorm.ErrRecordNotFound)

	var foundReplayedUser2 oplog_test.TestUser
	err = tx2.Where("id = ?", userCreate2.Id).First(&foundReplayedUser2).Error
	is.True(err == gorm.ErrRecordNotFound)

	tx2.Commit()
}

// Test_GetTicket provides unit tests for getting oplog.Tickets
func Test_GetTicket(t *testing.T) {
	startTest()
	t.Parallel()
	is, cleanup, url := setup(t)
	defer cleanup()
	defer completeTest() // must come after the "defer cleanup()"
	db, err := test_dbconn(url)
	is.NoErr(err)
	defer db.Close()

	ticketName, err := uuid.GenerateUUID()
	is.NoErr(err)
	ticketer := &GormTicketer{Tx: db}

	_, err = ticketer.InitTicket(ticketName)
	is.NoErr(err)
	ticket, err := ticketer.GetTicket(ticketName)
	is.NoErr(err)
	t.Logf("ticket: %+v", ticket)
}

// Test_TicketSerialization provides unit tests for making sure oplog.Tickets properly serialize writes to oplog entries
func Test_TicketSerialization(t *testing.T) {
	startTest()
	t.Parallel()
	is, cleanup, url := setup(t)
	defer cleanup()
	defer completeTest() // must come after the "defer cleanup()"
	db, err := test_dbconn(url)
	is.NoErr(err)
	defer db.Close()

	ticketName, err := uuid.GenerateUUID()
	is.NoErr(err)
	ticketer := &GormTicketer{Tx: db}

	// in it's own transaction, init the ticket
	_, _ = ticketer.InitTicket(ticketName)

	cipherer := initWrapper(t)

	id, err := uuid.GenerateUUID()
	is.NoErr(err)
	firstTx := db.Begin()
	firstUser := oplog_test.TestUser{
		Name: "foo-" + id,
	}
	err = firstTx.Create(&firstUser).Error
	is.NoErr(err)
	firstTicket, err := ticketer.GetTicket(ticketName)
	is.NoErr(err)

	firstQueue := Queue{}
	err = firstQueue.Add(&firstUser, "user", OpType_CreateOp)
	is.NoErr(err)

	firstLogEntry, err := NewEntry(
		"test-users",
		Metadata{
			"deployment": "amex",
			"project":    "central-info-systems",
		},
		cipherer,
		ticketer,
	)
	is.NoErr(err)

	firstLogEntry.Data = firstQueue.QueueBuffer
	id2, err := uuid.GenerateUUID()
	is.NoErr(err)
	secondTx := db.Begin()
	secondUser := oplog_test.TestUser{
		Name: "foo-" + id2,
	}
	err = secondTx.Create(&secondUser).Error
	is.NoErr(err)
	secondTicket, err := ticketer.GetTicket(ticketName)
	is.NoErr(err)

	secondQueue := Queue{}
	err = secondQueue.Add(&secondUser, "user", OpType_CreateOp)
	is.NoErr(err)

	secondLogEntry, err := NewEntry(
		"foobar",
		Metadata{
			"deployment": "amex",
			"project":    "central-info-systems",
		},
		cipherer,
		ticketer,
	)
	is.NoErr(err)
	secondLogEntry.Data = secondQueue.QueueBuffer

	err = secondLogEntry.Write(context.Background(), &GormWriter{secondTx}, secondTicket)
	is.NoErr(err)
	is.True(secondLogEntry.Id != 0)
	err = secondTx.Commit().Error
	is.NoErr(err)
	is.True(secondLogEntry.Id != 0)
	t.Log(secondLogEntry)

	err = firstLogEntry.Write(context.Background(), &GormWriter{firstTx}, firstTicket)
	if err != nil {
		t.Log(err)
		firstTx.Rollback()
	} else {
		firstTx.Commit()
		t.Error("should have failed to write firstLogEntry")
	}
}

// Test_WriteEntryWith provides unit tests for oplog.WriteEntryWith
func Test_WriteEntryWith(t *testing.T) {
	t.Parallel()
	startTest()
	is, cleanup, url := setup(t)
	defer cleanup()
	defer completeTest() // must come after the "defer cleanup()"
	db, err := test_dbconn(url)
	is.NoErr(err)
	defer db.Close()

	cipherer := initWrapper(t)

	id, err := uuid.GenerateUUID()
	is.NoErr(err)
	u := oplog_test.TestUser{
		Name: "foo-" + id,
	}
	t.Log(&u)

	id2, err := uuid.GenerateUUID()
	is.NoErr(err)
	u2 := oplog_test.TestUser{
		Name: "foo-" + id2,
	}
	t.Log(&u2)

	ticketName, err := uuid.GenerateUUID()
	is.NoErr(err)
	ticketer := &GormTicketer{Tx: db}

	_, err = ticketer.InitTicket(ticketName)
	is.NoErr(err)
	ticket, err := ticketer.GetTicket(ticketName)
	is.NoErr(err)

	is.NoErr(err)
	newLogEntry, err := NewEntry(
		"test-users",
		Metadata{
			"deployment": "amex",
			"project":    "central-info-systems",
		},
		cipherer,
		ticketer,
	)
	is.NoErr(err)
	err = newLogEntry.WriteEntryWith(context.Background(), &GormWriter{db}, ticket,
		&Message{Message: &u, TypeURL: "user", OpType: OpType_CreateOp},
		&Message{Message: &u2, TypeURL: "user", OpType: OpType_CreateOp})
	is.NoErr(err)

	var foundEntry Entry
	err = db.Where("id = ?", newLogEntry.Id).First(&foundEntry).Error
	is.NoErr(err)
	foundEntry.Cipherer = cipherer
	types, err := NewTypeCatalog(Type{new(oplog_test.TestUser), "user"})
	is.NoErr(err)
	err = foundEntry.DecryptData(context.Background())
	is.NoErr(err)
	foundUsers, err := foundEntry.UnmarshalData(types)
	is.NoErr(err)
	is.True(foundUsers[0].Message.(*oplog_test.TestUser).Name == u.Name)
	for _, m := range foundUsers {
		t.Log(m)
	}
}

// initDbInDocker initializes postgres within dockertest for the unit tests
func initDbInDocker(t *testing.T) (cleanup func(), retURL string, err error) {
	if os.Getenv("PG_URL") != "" {
		initTestStore(t, func() {}, os.Getenv("PG_URL"))
		return func() {}, os.Getenv("PG_URL"), nil
	}
	pool, err := dockertest.NewPool("")
	if err != nil {
		return func() {}, "", fmt.Errorf("could not connect to docker: %w", err)
	}

	resource, err := pool.Run("postgres", "latest", []string{"POSTGRES_PASSWORD=secret", "POSTGRES_DB=watchtower"})
	if err != nil {
		return func() {}, "", fmt.Errorf("could not start resource: %w", err)
	}

	c := func() {
		cleanupResource(t, pool, resource)
	}

	url := fmt.Sprintf("postgres://postgres:secret@localhost:%s?sslmode=disable", resource.GetPort("5432/tcp"))

	if err := pool.Retry(func() error {
		db, err := sql.Open("postgres", url)
		if err != nil {
			return fmt.Errorf("error opening postgres dev container: %w", err)
		}

		if err := db.Ping(); err != nil {
			return err
		}
		defer db.Close()
		return nil
	}); err != nil {
		return func() {}, "", fmt.Errorf("could not connect to docker: %w", err)
	}
	initTestStore(t, c, url)
	return c, url, nil
}

// initWrapper initializes an AEAD wrapping.Wrapper for testing the oplog
func initWrapper(t *testing.T) wrapping.Wrapper {
	rootKey := make([]byte, 32)
	n, err := rand.Read(rootKey)
	if err != nil {
		t.Fatal(err)
	}
	if n != 32 {
		t.Fatal(n)
	}
	root := aead.NewWrapper(nil)
	if err := root.SetAESGCMKeyBytes(rootKey); err != nil {
		t.Fatal(err)
	}
	return root
}

// initTestStore will execute the migrations needed to initialize the store for tests
func initTestStore(t *testing.T, cleanup func(), url string) {
	// run migrations
	m, err := migrate.New("file://migrations/postgres", url)
	if err != nil {
		cleanup()
		t.Fatalf("Error creating migrations: %s", err)
	}
	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		cleanup()
		t.Fatalf("Error running migrations: %s", err)
	}
}

// cleanupResource will clean up the dockertest resources (postgres)
func cleanupResource(t *testing.T, pool *dockertest.Pool, resource *dockertest.Resource) {
	waitForTests()
	var err error
	for i := 0; i < 10; i++ {
		err = pool.Purge(resource)
		if err == nil {
			return
		}
	}

	if strings.Contains(err.Error(), "No such container") {
		return
	}
	t.Fatalf("Failed to cleanup local container: %s", err)
}

func test_dbconn(url string) (*gorm.DB, error) {
	return gorm.Open("postgres", url)
}
