package db

import (
	"context"
	"errors"
	"testing"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/watchtower/internal/db/db_test"
	"github.com/hashicorp/watchtower/internal/oplog"
	"github.com/jinzhu/gorm"
	"gotest.tools/assert"
)

func TestGormReadWriter_Update(t *testing.T) {
	StartTest()
	t.Parallel()
	cleanup, url := SetupTest(t, "migrations/postgres")
	defer cleanup()
	defer CompleteTest() // must come after the "defer cleanup()"
	conn, err := TestConnection(url)
	assert.NilError(t, err)
	defer conn.Close()
	t.Run("simple", func(t *testing.T) {
		w := GormReadWriter{Tx: conn}
		id, err := uuid.GenerateUUID()
		assert.NilError(t, err)
		user, err := db_test.NewTestUser()
		assert.NilError(t, err)
		user.Name = "foo-" + id
		err = w.Create(context.Background(), user)
		assert.NilError(t, err)
		assert.Check(t, user.Id != 0)

		foundUser, err := db_test.NewTestUser()
		assert.NilError(t, err)
		foundUser.Id = user.Id
		err = w.LookupById(context.Background(), foundUser)
		assert.NilError(t, err)
		assert.Equal(t, user.Id, foundUser.Id)

		user.FriendlyName = "friendly-" + id
		err = w.Update(context.Background(), user, []string{"FriendlyName"})
		assert.NilError(t, err)

		err = w.LookupById(context.Background(), foundUser)
		assert.NilError(t, err)
		assert.Equal(t, user.FriendlyName, foundUser.FriendlyName)
	})
	t.Run("valid-WithOplog", func(t *testing.T) {
		w := GormReadWriter{Tx: conn}
		id, err := uuid.GenerateUUID()
		assert.NilError(t, err)
		user, err := db_test.NewTestUser()
		assert.NilError(t, err)
		user.Name = "foo-" + id
		err = w.Create(context.Background(), user)
		assert.NilError(t, err)
		assert.Check(t, user.Id != 0)

		foundUser, err := db_test.NewTestUser()
		assert.NilError(t, err)
		foundUser.Id = user.Id
		err = w.LookupById(context.Background(), foundUser)
		assert.NilError(t, err)
		assert.Equal(t, user.Id, foundUser.Id)

		user.FriendlyName = "friendly-" + id
		_, err = w.DoTx(
			context.Background(),
			20,           // twenty retries
			ExpBackoff{}, // exponential backoff
			func(w Writer) error {
				// the TxHandler updates the user's friendly name
				return w.Update(context.Background(), user, []string{"FriendlyName"},
					WithOplog(true), // write oplogs for this update
					WithWrapper(InitTestWrapper(t)),
					WithMetadata(oplog.Metadata{
						"key-only":   nil,
						"deployment": []string{"amex"},
						"project":    []string{"central-info-systems", "local-info-systems"},
					}),
				)
			})
		assert.NilError(t, err)

		err = w.LookupById(context.Background(), foundUser)
		assert.NilError(t, err)
		assert.Equal(t, user.FriendlyName, foundUser.FriendlyName)
	})
	t.Run("nil-tx", func(t *testing.T) {
		w := GormReadWriter{Tx: nil}
		id, err := uuid.GenerateUUID()
		assert.NilError(t, err)
		user, err := db_test.NewTestUser()
		assert.NilError(t, err)
		user.Name = "foo-" + id
		err = w.Update(context.Background(), user, nil)
		assert.Check(t, err != nil)
		assert.Equal(t, err.Error(), "update tx is nil")
	})
	t.Run("no-wrapper-WithOplog", func(t *testing.T) {
		w := GormReadWriter{Tx: conn}
		id, err := uuid.GenerateUUID()
		assert.NilError(t, err)
		user, err := db_test.NewTestUser()
		assert.NilError(t, err)
		user.Name = "foo-" + id
		err = w.Create(context.Background(), user)
		assert.NilError(t, err)
		assert.Check(t, user.Id != 0)

		foundUser, err := db_test.NewTestUser()
		assert.NilError(t, err)
		foundUser.Id = user.Id
		err = w.LookupById(context.Background(), foundUser)
		assert.NilError(t, err)
		assert.Equal(t, user.Id, foundUser.Id)

		user.FriendlyName = "friendly-" + id
		_, err = w.DoTx(
			context.Background(),
			20,
			ExpBackoff{},
			func(w Writer) error {
				return w.Update(context.Background(), user, []string{"FriendlyName"},
					WithOplog(true),
					WithMetadata(oplog.Metadata{
						"key-only":   nil,
						"deployment": []string{"amex"},
						"project":    []string{"central-info-systems", "local-info-systems"},
					}),
				)
			})
		assert.Check(t, err != nil)
		assert.Equal(t, err.Error(), "error wrapper is nil for WithWrapper")
	})
	t.Run("no-metadata-WithOplog", func(t *testing.T) {
		w := GormReadWriter{Tx: conn}
		id, err := uuid.GenerateUUID()
		assert.NilError(t, err)
		user, err := db_test.NewTestUser()
		assert.NilError(t, err)
		user.Name = "foo-" + id
		err = w.Create(context.Background(), user)
		assert.NilError(t, err)
		assert.Check(t, user.Id != 0)

		foundUser, err := db_test.NewTestUser()
		assert.NilError(t, err)
		foundUser.Id = user.Id
		err = w.LookupById(context.Background(), foundUser)
		assert.NilError(t, err)
		assert.Equal(t, user.Id, foundUser.Id)

		user.FriendlyName = "friendly-" + id
		_, err = w.DoTx(
			context.Background(),
			20,
			ExpBackoff{},
			func(w Writer) error {
				return w.Update(context.Background(), user, []string{"FriendlyName"},
					WithOplog(true),
					WithWrapper(InitTestWrapper(t)),
				)
			})
		assert.Check(t, err != nil)
		assert.Equal(t, err.Error(), "error no metadata for WithOplog")
	})
}

func TestGormReadWriter_Create(t *testing.T) {
	StartTest()
	t.Parallel()
	cleanup, url := SetupTest(t, "migrations/postgres")
	defer cleanup()
	defer CompleteTest() // must come after the "defer cleanup()"
	conn, err := TestConnection(url)
	assert.NilError(t, err)
	defer conn.Close()
	t.Run("simple", func(t *testing.T) {
		w := GormReadWriter{Tx: conn}
		id, err := uuid.GenerateUUID()
		assert.NilError(t, err)
		user, err := db_test.NewTestUser()
		assert.NilError(t, err)
		user.Name = "foo-" + id
		err = w.Create(context.Background(), user)
		assert.NilError(t, err)
		assert.Check(t, user.Id != 0)
		assert.Check(t, user.GetCreateTime() != nil)
		assert.Check(t, user.GetUpdateTime() != nil)

		foundUser, err := db_test.NewTestUser()
		assert.NilError(t, err)
		foundUser.Id = user.Id
		err = w.LookupById(context.Background(), foundUser)
		assert.NilError(t, err)
		assert.Equal(t, user.Id, foundUser.Id)
	})
	t.Run("valid-WithOplog", func(t *testing.T) {
		w := GormReadWriter{Tx: conn}
		id, err := uuid.GenerateUUID()
		assert.NilError(t, err)
		user, err := db_test.NewTestUser()
		assert.NilError(t, err)
		user.Name = "foo-" + id
		var returnedUser *db_test.TestUser
		_, err = w.DoTx(
			context.Background(),
			3,
			ExpBackoff{},
			func(w Writer) error {
				// make sure you used the passed in writer that properly handles transaction rollback
				// we need to clone the user before every attempt to insert it, since it will be retried
				returnedUser = user.Clone()
				return w.Create(
					context.Background(),
					returnedUser,
					WithOplog(true),
					WithWrapper(InitTestWrapper(t)),
					WithMetadata(oplog.Metadata{
						"key-only":   nil,
						"deployment": []string{"amex"},
						"project":    []string{"central-info-systems", "local-info-systems"},
					}),
				)
			})
		assert.NilError(t, err)
		assert.Check(t, returnedUser.Id != 0)

		foundUser, err := db_test.NewTestUser()
		assert.NilError(t, err)
		foundUser.Id = returnedUser.Id
		err = w.LookupById(context.Background(), foundUser)
		assert.NilError(t, err)
		assert.Equal(t, returnedUser.Id, foundUser.Id)
	})
	t.Run("no-wrapper-WithOplog", func(t *testing.T) {
		w := GormReadWriter{Tx: conn}
		id, err := uuid.GenerateUUID()
		assert.NilError(t, err)
		user, err := db_test.NewTestUser()
		assert.NilError(t, err)
		user.Name = "foo-" + id
		_, err = w.DoTx(
			context.Background(),
			3,
			ExpBackoff{},
			func(w Writer) error {
				retryableUser := user.Clone()
				return w.Create(
					context.Background(),
					retryableUser,
					WithOplog(true),
					WithMetadata(oplog.Metadata{
						"key-only":   nil,
						"deployment": []string{"amex"},
						"project":    []string{"central-info-systems", "local-info-systems"},
					}),
				)
			})
		assert.Check(t, err != nil)
		assert.Equal(t, err.Error(), "error wrapper is nil for WithWrapper")
	})
	t.Run("no-metadata-WithOplog", func(t *testing.T) {
		w := GormReadWriter{Tx: conn}
		id, err := uuid.GenerateUUID()
		assert.NilError(t, err)
		user, err := db_test.NewTestUser()
		assert.NilError(t, err)
		user.Name = "foo-" + id
		_, err = w.DoTx(
			context.Background(),
			3,
			ExpBackoff{},
			func(w Writer) error {
				retryableUser := user.Clone()
				return w.Create(
					context.Background(),
					retryableUser,
					WithOplog(true),
					WithWrapper(InitTestWrapper(t)),
				)
			})
		assert.Check(t, err != nil)
		assert.Equal(t, err.Error(), "error no metadata for WithOplog")
	})
	t.Run("nil-tx", func(t *testing.T) {
		w := GormReadWriter{Tx: nil}
		id, err := uuid.GenerateUUID()
		assert.NilError(t, err)
		user, err := db_test.NewTestUser()
		assert.NilError(t, err)
		user.Name = "foo-" + id
		err = w.Create(context.Background(), user)
		assert.Check(t, err != nil)
		assert.Equal(t, err.Error(), "create tx is nil")
	})
}

func TestGormReadWriter_LookupByInternalId(t *testing.T) {
	StartTest()
	t.Parallel()
	cleanup, url := SetupTest(t, "migrations/postgres")
	defer cleanup()
	defer CompleteTest() // must come after the "defer cleanup()"
	conn, err := TestConnection(url)
	assert.NilError(t, err)
	defer conn.Close()
	t.Run("simple", func(t *testing.T) {
		w := GormReadWriter{Tx: conn}
		id, err := uuid.GenerateUUID()
		assert.NilError(t, err)
		user, err := db_test.NewTestUser()
		assert.NilError(t, err)
		user.Name = "foo-" + id
		err = w.Create(context.Background(), user)
		assert.NilError(t, err)
		assert.Check(t, user.Id != 0)

		foundUser, err := db_test.NewTestUser()
		assert.NilError(t, err)
		foundUser.Id = user.Id
		err = w.LookupById(context.Background(), foundUser)
		assert.NilError(t, err)
		assert.Equal(t, user.Id, foundUser.Id)
	})
	t.Run("tx-nil,", func(t *testing.T) {
		w := GormReadWriter{}
		foundUser, err := db_test.NewTestUser()
		assert.NilError(t, err)
		err = w.LookupById(context.Background(), foundUser)
		assert.Check(t, err != nil)
		assert.Equal(t, err.Error(), "error tx nil for lookup by internal id")
	})
	t.Run("no-public-id-set", func(t *testing.T) {
		w := GormReadWriter{Tx: conn}
		foundUser, err := db_test.NewTestUser()
		assert.NilError(t, err)
		err = w.LookupById(context.Background(), foundUser)
		assert.Check(t, err != nil)
		assert.Equal(t, err.Error(), "error internal id is 0 for lookup by internal id")
	})
	t.Run("not-found", func(t *testing.T) {
		w := GormReadWriter{Tx: conn}
		foundUser, err := db_test.NewTestUser()
		assert.NilError(t, err)
		foundUser.Id = 4294967295 // we should never get to the max for unit32
		err = w.LookupById(context.Background(), foundUser)
		assert.Check(t, err != nil)
		assert.Equal(t, err, gorm.ErrRecordNotFound)
	})
}

func TestGormReadWriter_LookupByFriendlyName(t *testing.T) {
	StartTest()
	t.Parallel()
	cleanup, url := SetupTest(t, "migrations/postgres")
	defer cleanup()
	defer CompleteTest() // must come after the "defer cleanup()"
	conn, err := TestConnection(url)
	assert.NilError(t, err)
	defer conn.Close()
	t.Run("simple", func(t *testing.T) {
		w := GormReadWriter{Tx: conn}
		id, err := uuid.GenerateUUID()
		assert.NilError(t, err)
		user, err := db_test.NewTestUser()
		assert.NilError(t, err)
		user.Name = "foo-" + id
		user.FriendlyName = "fn-" + id
		err = w.Create(context.Background(), user)
		assert.NilError(t, err)
		assert.Check(t, user.Id != 0)

		foundUser, err := db_test.NewTestUser()
		assert.NilError(t, err)
		foundUser.FriendlyName = "fn-" + id
		err = w.LookupByFriendlyName(context.Background(), foundUser)
		assert.NilError(t, err)
		assert.Equal(t, user.Id, foundUser.Id)
	})
	t.Run("tx-nil,", func(t *testing.T) {
		w := GormReadWriter{}
		foundUser, err := db_test.NewTestUser()
		assert.NilError(t, err)
		foundUser.FriendlyName = "fn-name"
		err = w.LookupByFriendlyName(context.Background(), foundUser)
		assert.Check(t, err != nil)
		assert.Equal(t, err.Error(), "error tx nil for lookup by friendly name")
	})
	t.Run("no-friendly-name-set", func(t *testing.T) {
		w := GormReadWriter{Tx: conn}
		foundUser, err := db_test.NewTestUser()
		assert.NilError(t, err)
		err = w.LookupByFriendlyName(context.Background(), foundUser)
		assert.Check(t, err != nil)
		assert.Equal(t, err.Error(), "error friendly name empty string for lookup by friendly name")
	})
	t.Run("not-found", func(t *testing.T) {
		w := GormReadWriter{Tx: conn}
		id, err := uuid.GenerateUUID()
		assert.NilError(t, err)

		foundUser, err := db_test.NewTestUser()
		assert.NilError(t, err)
		foundUser.FriendlyName = "fn-" + id
		err = w.LookupByFriendlyName(context.Background(), foundUser)
		assert.Check(t, err != nil)
		assert.Equal(t, err, gorm.ErrRecordNotFound)
	})
}

func TestGormReadWriter_LookupByPublicId(t *testing.T) {
	StartTest()
	t.Parallel()
	cleanup, url := SetupTest(t, "migrations/postgres")
	defer cleanup()
	defer CompleteTest() // must come after the "defer cleanup()"
	conn, err := TestConnection(url)
	assert.NilError(t, err)
	defer conn.Close()
	t.Run("simple", func(t *testing.T) {
		w := GormReadWriter{Tx: conn}
		id, err := uuid.GenerateUUID()
		assert.NilError(t, err)
		user, err := db_test.NewTestUser()
		assert.NilError(t, err)
		user.Name = "foo-" + id
		user.FriendlyName = "fn-" + id
		err = w.Create(context.Background(), user)
		assert.NilError(t, err)
		assert.Check(t, user.PublicId != "")

		foundUser, err := db_test.NewTestUser()
		assert.NilError(t, err)
		foundUser.PublicId = user.PublicId
		err = w.LookupByPublicId(context.Background(), foundUser)
		assert.NilError(t, err)
		assert.Equal(t, user.Id, foundUser.Id)
	})
	t.Run("tx-nil,", func(t *testing.T) {
		w := GormReadWriter{}
		foundUser, err := db_test.NewTestUser()
		assert.NilError(t, err)
		err = w.LookupByPublicId(context.Background(), foundUser)
		assert.Check(t, err != nil)
		assert.Equal(t, err.Error(), "error tx nil for lookup by public id")
	})
	t.Run("no-public-id-set", func(t *testing.T) {
		w := GormReadWriter{Tx: conn}
		foundUser, err := db_test.NewTestUser()
		foundUser.PublicId = ""
		assert.NilError(t, err)
		err = w.LookupByPublicId(context.Background(), foundUser)
		assert.Check(t, err != nil)
		assert.Equal(t, err.Error(), "error public id empty string for lookup by public id")
	})
	t.Run("not-found", func(t *testing.T) {
		w := GormReadWriter{Tx: conn}
		id, err := uuid.GenerateUUID()
		assert.NilError(t, err)

		foundUser, err := db_test.NewTestUser()
		assert.NilError(t, err)
		foundUser.PublicId = id
		err = w.LookupByPublicId(context.Background(), foundUser)
		assert.Check(t, err != nil)
		assert.Equal(t, err, gorm.ErrRecordNotFound)
	})
}

func TestGormReadWriter_LookupBy(t *testing.T) {
	StartTest()
	t.Parallel()
	cleanup, url := SetupTest(t, "migrations/postgres")
	defer cleanup()
	defer CompleteTest() // must come after the "defer cleanup()"
	conn, err := TestConnection(url)
	assert.NilError(t, err)
	defer conn.Close()
	t.Run("simple", func(t *testing.T) {
		w := GormReadWriter{Tx: conn}
		id, err := uuid.GenerateUUID()
		assert.NilError(t, err)
		user, err := db_test.NewTestUser()
		assert.NilError(t, err)
		user.Name = "foo-" + id
		user.FriendlyName = "fn-" + id
		err = w.Create(context.Background(), user)
		assert.NilError(t, err)
		assert.Check(t, user.PublicId != "")

		var foundUser db_test.TestUser
		err = w.LookupBy(context.Background(), &foundUser, "public_id = ?", user.PublicId)
		assert.NilError(t, err)
		assert.Equal(t, user.Id, foundUser.Id)
	})
	t.Run("tx-nil,", func(t *testing.T) {
		w := GormReadWriter{}
		var foundUser db_test.TestUser
		err = w.LookupBy(context.Background(), &foundUser, "public_id = ?", 1)
		assert.Check(t, err != nil)
		assert.Equal(t, err.Error(), "error tx nil for lookup by")
	})
	t.Run("not-found", func(t *testing.T) {
		w := GormReadWriter{Tx: conn}
		id, err := uuid.GenerateUUID()
		assert.NilError(t, err)

		var foundUser db_test.TestUser
		err = w.LookupBy(context.Background(), &foundUser, "public_id = ?", id)
		assert.Check(t, err != nil)
		assert.Equal(t, err, gorm.ErrRecordNotFound)
	})
	t.Run("bad-where", func(t *testing.T) {
		w := GormReadWriter{Tx: conn}
		id, err := uuid.GenerateUUID()
		assert.NilError(t, err)

		var foundUser db_test.TestUser
		err = w.LookupBy(context.Background(), &foundUser, "? = ?", id)
		assert.Check(t, err != nil)
	})
}

func TestGormReadWriter_SearchBy(t *testing.T) {
	StartTest()
	t.Parallel()
	cleanup, url := SetupTest(t, "migrations/postgres")
	defer cleanup()
	defer CompleteTest() // must come after the "defer cleanup()"
	conn, err := TestConnection(url)
	assert.NilError(t, err)
	defer conn.Close()
	t.Run("simple", func(t *testing.T) {
		w := GormReadWriter{Tx: conn}
		id, err := uuid.GenerateUUID()
		assert.NilError(t, err)
		user, err := db_test.NewTestUser()
		assert.NilError(t, err)
		user.Name = "foo-" + id
		user.FriendlyName = "fn-" + id
		err = w.Create(context.Background(), user)
		assert.NilError(t, err)
		assert.Check(t, user.PublicId != "")

		var foundUsers []db_test.TestUser
		err = w.SearchBy(context.Background(), &foundUsers, "public_id = ?", user.PublicId)
		assert.NilError(t, err)
		assert.Equal(t, user.Id, foundUsers[0].Id)
	})
	t.Run("tx-nil,", func(t *testing.T) {
		w := GormReadWriter{}
		var foundUsers []db_test.TestUser
		err = w.SearchBy(context.Background(), &foundUsers, "public_id = ?", 1)
		assert.Check(t, err != nil)
		assert.Equal(t, err.Error(), "error tx nil for search by")
	})
	t.Run("not-found", func(t *testing.T) {
		w := GormReadWriter{Tx: conn}
		id, err := uuid.GenerateUUID()
		assert.NilError(t, err)

		var foundUsers []db_test.TestUser
		err = w.SearchBy(context.Background(), &foundUsers, "public_id = ?", id)
		assert.NilError(t, err)
		assert.Equal(t, len(foundUsers), 0)
	})
	t.Run("bad-where", func(t *testing.T) {
		w := GormReadWriter{Tx: conn}
		id, err := uuid.GenerateUUID()
		assert.NilError(t, err)

		var foundUsers []db_test.TestUser
		err = w.SearchBy(context.Background(), &foundUsers, "? = ?", id)
		assert.Check(t, err != nil)
	})
}

func TestGormReadWriter_Dialect(t *testing.T) {
	StartTest()
	t.Parallel()
	cleanup, url := SetupTest(t, "migrations/postgres")
	defer cleanup()
	defer CompleteTest() // must come after the "defer cleanup()"
	conn, err := TestConnection(url)
	assert.NilError(t, err)
	defer conn.Close()
	t.Run("valid", func(t *testing.T) {
		w := GormReadWriter{Tx: conn}
		d, err := w.Dialect()
		assert.NilError(t, err)
		assert.Equal(t, d, "postgres")
	})
	t.Run("nil-tx", func(t *testing.T) {
		w := GormReadWriter{Tx: nil}
		d, err := w.Dialect()
		assert.Check(t, err != nil)
		assert.Equal(t, d, "")
		assert.Equal(t, err.Error(), "create tx is nil for dialect")
	})
}

func TestGormReadWriter_DB(t *testing.T) {
	StartTest()
	t.Parallel()
	cleanup, url := SetupTest(t, "migrations/postgres")
	defer cleanup()
	defer CompleteTest() // must come after the "defer cleanup()"
	conn, err := TestConnection(url)
	assert.NilError(t, err)
	defer conn.Close()
	t.Run("valid", func(t *testing.T) {
		w := GormReadWriter{Tx: conn}
		d, err := w.DB()
		assert.NilError(t, err)
		assert.Check(t, d != nil)
		err = d.Ping()
		assert.NilError(t, err)
	})
	t.Run("nil-tx", func(t *testing.T) {
		w := GormReadWriter{Tx: nil}
		d, err := w.DB()
		assert.Check(t, err != nil)
		assert.Check(t, d == nil)
		assert.Equal(t, err.Error(), "create tx is nil for db")
	})
}

func TestGormReadWriter_DoTx(t *testing.T) {
	StartTest()
	t.Parallel()
	cleanup, url := SetupTest(t, "migrations/postgres")
	defer cleanup()
	defer CompleteTest() // must come after the "defer cleanup()"
	conn, err := TestConnection(url)
	assert.NilError(t, err)
	defer conn.Close()

	t.Run("valid-with-10-retries", func(t *testing.T) {
		w := &GormReadWriter{Tx: conn}
		retries := 0
		got, err := w.DoTx(context.Background(), 10, ExpBackoff{},
			func(Writer) error {
				retries += 1
				if retries < 9 {
					return oplog.ErrTicketAlreadyRedeemed
				}
				return nil
			})
		assert.NilError(t, err)
		assert.Equal(t, got.Retries, 8)
		assert.Equal(t, retries, 9) // attempted 1 + 8 retries
	})
	t.Run("zero-retries", func(t *testing.T) {
		w := &GormReadWriter{Tx: conn}
		retries := 0
		got, err := w.DoTx(context.Background(), 0, ExpBackoff{}, func(Writer) error { retries += 1; return nil })
		assert.NilError(t, err)
		assert.Equal(t, got, RetryInfo{})
		assert.Equal(t, retries, 1)
	})
	t.Run("nil-tx", func(t *testing.T) {
		w := &GormReadWriter{nil}
		retries := 0
		got, err := w.DoTx(context.Background(), 1, ExpBackoff{}, func(Writer) error { retries += 1; return nil })
		assert.Check(t, err != nil)
		assert.Equal(t, got, RetryInfo{})
		assert.Equal(t, err.Error(), "do tx is nil")
	})
	t.Run("not-a-retry-err", func(t *testing.T) {
		w := &GormReadWriter{Tx: conn}
		got, err := w.DoTx(context.Background(), 1, ExpBackoff{}, func(Writer) error { return errors.New("not a retry error") })
		assert.Check(t, err != nil)
		assert.Equal(t, got, RetryInfo{})
		assert.Check(t, err != oplog.ErrTicketAlreadyRedeemed)
	})
	t.Run("too-many-retries", func(t *testing.T) {
		w := &GormReadWriter{Tx: conn}
		retries := 0
		got, err := w.DoTx(context.Background(), 2, ExpBackoff{}, func(Writer) error { retries += 1; return oplog.ErrTicketAlreadyRedeemed })
		assert.Check(t, err != nil)
		assert.Equal(t, got.Retries, 1)
		assert.Equal(t, err.Error(), "Too many retries: 2 of 2")
	})
}

func TestGormReadWriter_Delete(t *testing.T) {
	StartTest()
	t.Parallel()
	cleanup, url := SetupTest(t, "migrations/postgres")
	defer cleanup()
	defer CompleteTest() // must come after the "defer cleanup()"
	conn, err := TestConnection(url)
	assert.NilError(t, err)
	defer conn.Close()
	t.Run("simple", func(t *testing.T) {
		w := GormReadWriter{Tx: conn}
		id, err := uuid.GenerateUUID()
		assert.NilError(t, err)
		user, err := db_test.NewTestUser()
		assert.NilError(t, err)
		user.Name = "foo-" + id
		err = w.Create(context.Background(), user)
		assert.NilError(t, err)
		assert.Check(t, user.Id != 0)
		assert.Check(t, user.GetCreateTime() != nil)
		assert.Check(t, user.GetUpdateTime() != nil)

		foundUser, err := db_test.NewTestUser()
		assert.NilError(t, err)
		foundUser.Id = user.Id
		err = w.LookupById(context.Background(), foundUser)
		assert.NilError(t, err)
		assert.Equal(t, user.Id, foundUser.Id)

		err = w.Delete(context.Background(), user)
		assert.NilError(t, err)

		err = w.LookupById(context.Background(), foundUser)
		assert.Check(t, err != nil)
		assert.Equal(t, err, gorm.ErrRecordNotFound)
	})
	t.Run("valid-WithOplog", func(t *testing.T) {
		w := GormReadWriter{Tx: conn}
		id, err := uuid.GenerateUUID()
		assert.NilError(t, err)
		user, err := db_test.NewTestUser()
		assert.NilError(t, err)
		user.Name = "foo-" + id
		var returnedUser *db_test.TestUser
		_, err = w.DoTx(
			context.Background(),
			10,
			ExpBackoff{},
			func(w Writer) error {
				// make sure you used the passed in writer that properly handles transaction rollback
				// we need to clone the user before every attempt to insert it, since it will be retried
				returnedUser = user.Clone()
				err := w.Create(
					context.Background(),
					returnedUser,
					WithOplog(true),
					WithWrapper(InitTestWrapper(t)),
					WithMetadata(oplog.Metadata{
						"key-only":   nil,
						"deployment": []string{"amex"},
						"project":    []string{"central-info-systems", "local-info-systems"},
					}),
				)
				return err
			})
		assert.NilError(t, err)
		assert.Check(t, returnedUser.Id != 0)

		foundUser, err := db_test.NewTestUser()
		assert.NilError(t, err)
		foundUser.Id = returnedUser.Id
		err = w.LookupById(context.Background(), foundUser)
		assert.NilError(t, err)
		assert.Equal(t, returnedUser.Id, foundUser.Id)

		err = w.Delete(
			context.Background(),
			returnedUser,
			WithOplog(true),
			WithWrapper(InitTestWrapper(t)),
			WithMetadata(oplog.Metadata{
				"key-only":   nil,
				"deployment": []string{"amex"},
				"project":    []string{"central-info-systems", "local-info-systems"},
			}),
		)
		assert.NilError(t, err)

		err = w.LookupById(context.Background(), foundUser)
		assert.Check(t, err != nil)
		assert.Equal(t, err, gorm.ErrRecordNotFound)
	})
	t.Run("no-wrapper-WithOplog", func(t *testing.T) {
		w := GormReadWriter{Tx: conn}
		id, err := uuid.GenerateUUID()
		assert.NilError(t, err)
		user, err := db_test.NewTestUser()
		assert.NilError(t, err)
		user.Name = "foo-" + id
		var returnedUser *db_test.TestUser
		_, err = w.DoTx(
			context.Background(),
			3,
			ExpBackoff{},
			func(w Writer) error {
				// make sure you used the passed in writer that properly handles transaction rollback
				// we need to clone the user before every attempt to insert it, since it will be retried
				returnedUser = user.Clone()
				return w.Create(
					context.Background(),
					returnedUser,
					WithOplog(true),
					WithWrapper(InitTestWrapper(t)),
					WithMetadata(oplog.Metadata{
						"key-only":   nil,
						"deployment": []string{"amex"},
						"project":    []string{"central-info-systems", "local-info-systems"},
					}),
				)
			})
		assert.NilError(t, err)
		assert.Check(t, returnedUser.Id != 0)

		foundUser, err := db_test.NewTestUser()
		assert.NilError(t, err)
		foundUser.Id = returnedUser.Id
		err = w.LookupById(context.Background(), foundUser)
		assert.NilError(t, err)
		assert.Equal(t, returnedUser.Id, foundUser.Id)

		err = w.Delete(
			context.Background(),
			returnedUser,
			WithOplog(true),
			WithMetadata(oplog.Metadata{
				"key-only":   nil,
				"deployment": []string{"amex"},
				"project":    []string{"central-info-systems", "local-info-systems"},
			}),
		)
		assert.Check(t, err != nil)
		assert.Equal(t, err.Error(), "error wrapper is nil for WithWrapper")
	})
	t.Run("no-metadata-WithOplog", func(t *testing.T) {
		w := GormReadWriter{Tx: conn}
		id, err := uuid.GenerateUUID()
		assert.NilError(t, err)
		user, err := db_test.NewTestUser()
		assert.NilError(t, err)
		user.Name = "foo-" + id
		var returnedUser *db_test.TestUser
		_, err = w.DoTx(
			context.Background(),
			3,
			ExpBackoff{},
			func(w Writer) error {
				// make sure you used the passed in writer that properly handles transaction rollback
				// we need to clone the user before every attempt to insert it, since it will be retried
				returnedUser = user.Clone()
				return w.Create(
					context.Background(),
					returnedUser,
					WithOplog(true),
					WithWrapper(InitTestWrapper(t)),
					WithMetadata(oplog.Metadata{
						"key-only":   nil,
						"deployment": []string{"amex"},
						"project":    []string{"central-info-systems", "local-info-systems"},
					}),
				)
			})
		assert.NilError(t, err)
		assert.Check(t, returnedUser.Id != 0)

		foundUser, err := db_test.NewTestUser()
		assert.NilError(t, err)
		foundUser.Id = returnedUser.Id
		err = w.LookupById(context.Background(), foundUser)
		assert.NilError(t, err)
		assert.Equal(t, returnedUser.Id, foundUser.Id)

		err = w.Delete(
			context.Background(),
			returnedUser,
			WithOplog(true),
			WithWrapper(InitTestWrapper(t)),
		)
		assert.Check(t, err != nil)
		assert.Equal(t, err.Error(), "error no metadata for WithOplog")
	})
	t.Run("nil-tx", func(t *testing.T) {
		w := GormReadWriter{Tx: nil}
		id, err := uuid.GenerateUUID()
		assert.NilError(t, err)
		user, err := db_test.NewTestUser()
		assert.NilError(t, err)
		user.Name = "foo-" + id
		err = w.Create(context.Background(), user)
		assert.Check(t, err != nil)
		assert.Equal(t, err.Error(), "create tx is nil")
	})
}

func TestGormReadWriter_ScanRows(t *testing.T) {
	StartTest()
	t.Parallel()
	cleanup, url := SetupTest(t, "migrations/postgres")
	defer cleanup()
	defer CompleteTest() // must come after the "defer cleanup()"
	conn, err := TestConnection(url)
	assert.NilError(t, err)
	defer conn.Close()
	t.Run("valid", func(t *testing.T) {
		w := GormReadWriter{Tx: conn}
		user, err := db_test.NewTestUser()
		assert.NilError(t, err)
		err = w.Create(context.Background(), user)
		assert.NilError(t, err)
		assert.Check(t, user.Id != 0)

		tx, err := w.DB()
		where := "select * from db_test_user where friendly_name in ($1, $2)"
		rows, err := tx.Query(where, "alice", "bob")
		defer rows.Close()
		for rows.Next() {
			u, err := db_test.NewTestUser()
			assert.NilError(t, err)

			// scan the row into your Gorm struct
			err = w.ScanRows(rows, &u)
			assert.NilError(t, err)
			assert.Equal(t, u.PublicId, user.PublicId)
		}
	})
}
