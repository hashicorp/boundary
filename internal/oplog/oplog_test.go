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
	"time"

	"github.com/google/uuid"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/go-kms-wrapping/wrappers/aead"
	"github.com/hashicorp/watchtower/internal/oplog/any"
	"github.com/hashicorp/watchtower/internal/oplog/oplog_test"
	"github.com/hashicorp/watchtower/internal/oplog/store"
	"github.com/jinzhu/gorm"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/matryer/is"
	"github.com/ory/dockertest/v3"
)

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
	is, cleanup, url := setup(t)
	defer cleanup()
	db, err := test_dbconn(url)
	is.NoErr(err)
	defer db.Close()

	cipherer := initWrapper(t)

	user := oplog_test.TestUser{
		Name: "foo-" + uuid.New().String(),
	}

	resp := db.Create(&user)
	is.NoErr(resp.Error)

	types, err := any.NewTypeCatalog(new(oplog_test.TestUser))
	is.NoErr(err)
	queue := any.Queue{Catalog: types}

	err = queue.Add(&user, any.OpType_CreateOp)
	is.NoErr(err)
	l := Entry{
		Entry: &store.Entry{
			AggregateName: "test-users",
			Data:          queue.QueueBuffer,
			Metadata: []*store.Metadata{
				&store.Metadata{
					Key:   "deployment",
					Value: "amex",
				},
				&store.Metadata{
					Key:   "project",
					Value: "central-info-systems",
				},
			},
		},
		Cipherer: cipherer,
	}
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

	// now let's us optimistic locking via a ticketing system for a serialized oplog
	ticketName := uuid.New().String()
	ticketer := &GormTicketer{Tx: db}
	_, err = ticketer.InitTicket(ticketName)
	is.NoErr(err)
	ticket, err := ticketer.GetTicket(ticketName)
	is.NoErr(err)

	queue = any.Queue{}
	err = queue.Add(&user, any.OpType_CreateOp)
	is.NoErr(err)

	newLogEntry := Entry{
		Entry: &store.Entry{
			AggregateName: "test-users",
			Data:          queue.QueueBuffer,
			Metadata: []*store.Metadata{
				&store.Metadata{
					Key:   "deployment",
					Value: "amex",
				},
				&store.Metadata{
					Key:   "project",
					Value: "central-info-systems",
				},
			},
		},
		Cipherer: cipherer,
		Ticketer: ticketer,
	}
	err = newLogEntry.Write(context.Background(), &GormWriter{db}, ticket)
	is.NoErr(err)
	is.True(newLogEntry.Id != 0)
	foundUsers, err = foundEntry.UnmarshalData(types)
	is.NoErr(err)
	is.True(foundUsers[0].Message.(*oplog_test.TestUser).Name == user.Name)
}

// Test_GetTicket provides unit tests for getting oplog.Tickets
func Test_GetTicket(t *testing.T) {
	t.Parallel()
	is, cleanup, url := setup(t)
	defer cleanup()
	db, err := test_dbconn(url)
	is.NoErr(err)
	defer db.Close()

	ticketName := uuid.New().String()
	ticketer := &GormTicketer{Tx: db}

	_, err = ticketer.InitTicket(ticketName)
	is.NoErr(err)
	ticket, err := ticketer.GetTicket(ticketName)
	is.NoErr(err)
	t.Logf("ticket: %+v", ticket)
}

// Test_TicketSerialization provides unit tests for making sure oplog.Tickets properly serialize writes to oplog entries
func Test_TicketSerialization(t *testing.T) {
	t.Parallel()
	is, cleanup, url := setup(t)
	defer cleanup()
	db, err := test_dbconn(url)
	is.NoErr(err)
	defer db.Close()

	ticketName := "test-aws-root"
	ticketer := &GormTicketer{Tx: db}

	// in it's own transaction, init the ticket
	_, _ = ticketer.InitTicket(ticketName)

	cipherer := initWrapper(t)

	firstTx := db.Begin()
	firstUser := oplog_test.TestUser{
		Name: "foo-" + uuid.New().String(),
	}
	err = firstTx.Create(&firstUser).Error
	is.NoErr(err)
	firstTicket, err := ticketer.GetTicket("test-aws-root")
	is.NoErr(err)

	firstQueue := any.Queue{}
	err = firstQueue.Add(&firstUser, any.OpType_CreateOp)
	is.NoErr(err)

	firstLogEntry := Entry{
		Entry: &store.Entry{
			AggregateName: "test-users",
			Data:          firstQueue.QueueBuffer,
			Metadata: []*store.Metadata{
				&store.Metadata{
					Key:   "deployment",
					Value: "amex",
				},
				&store.Metadata{
					Key:   "project",
					Value: "central-info-systems",
				},
			},
		},
		Cipherer: cipherer,
		Ticketer: ticketer,
	}

	secondTx := db.Begin()
	secondUser := oplog_test.TestUser{
		Name: "foo-" + uuid.New().String(),
	}
	err = secondTx.Create(&secondUser).Error
	is.NoErr(err)
	secondTicket, err := ticketer.GetTicket("test-aws-root")
	is.NoErr(err)

	secondQueue := any.Queue{}
	err = secondQueue.Add(&secondUser, any.OpType_CreateOp)
	is.NoErr(err)

	secondLogEntry := Entry{
		Entry: &store.Entry{
			AggregateName: "foobar",
			Data:          secondQueue.QueueBuffer,
			Metadata: []*store.Metadata{
				&store.Metadata{
					Key:   "deployment",
					Value: "amex",
				},
				&store.Metadata{
					Key:   "project",
					Value: "central-info-systems",
				},
			},
		},
		Cipherer: cipherer,
		Ticketer: ticketer,
	}
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
	is, cleanup, url := setup(t)
	defer cleanup()
	db, err := test_dbconn(url)
	is.NoErr(err)
	defer db.Close()

	cipherer := initWrapper(t)

	u := oplog_test.TestUser{
		Name: "foo-" + uuid.New().String(),
	}
	t.Log(u)
	u2 := oplog_test.TestUser{
		Name: "foo-" + uuid.New().String(),
	}
	t.Log(u2)
	ticketName := uuid.New().String()
	ticketer := &GormTicketer{Tx: db}

	_, err = ticketer.InitTicket(ticketName)
	is.NoErr(err)
	ticket, err := ticketer.GetTicket(ticketName)
	is.NoErr(err)

	is.NoErr(err)
	newLogEntry := Entry{
		Entry: &store.Entry{
			AggregateName: "test-users",
			Metadata: []*store.Metadata{
				&store.Metadata{
					Key:   "deployment",
					Value: "amex",
				},
				&store.Metadata{
					Key:   "project",
					Value: "central-info-systems",
				},
			},
		},
		Cipherer: cipherer,
		Ticketer: ticketer,
	}
	err = newLogEntry.WriteEntryWith(context.Background(), &GormWriter{db}, ticket, &Message{&u, any.OpType_CreateOp}, &Message{&u2, any.OpType_CreateOp})
	is.NoErr(err)

	var foundEntry Entry
	err = db.Where("id = ?", newLogEntry.Id).First(&foundEntry).Error
	is.NoErr(err)
	foundEntry.Cipherer = cipherer
	types, err := any.NewTypeCatalog(new(oplog_test.TestUser))
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
	var err error
	for i := 0; i < 10; i++ {
		err = pool.Purge(resource)
		if err == nil {
			return
		}
		time.Sleep(1 * time.Second)
	}

	if strings.Contains(err.Error(), "No such container") {
		return
	}
	t.Fatalf("Failed to cleanup local container: %s", err)
}

func test_dbconn(url string) (*gorm.DB, error) {
	return gorm.Open("postgres", url)
}
