package db

import (
	"context"
	"errors"
	"testing"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/watchtower/internal/db/db_test"
	"github.com/hashicorp/watchtower/internal/oplog"
	"github.com/jinzhu/gorm"
	"github.com/stretchr/testify/assert"
)

func TestGormReadWriter_Update(t *testing.T) {
	StartTest()
	t.Parallel()
	cleanup, url := SetupTest(t, "migrations/postgres")
	defer cleanup()
	defer CompleteTest() // must come after the "defer cleanup()"
	conn, err := TestConnection(url)
	assert := assert.New(t)
	assert.Nil(err)
	defer conn.Close()
	t.Run("simple", func(t *testing.T) {
		w := GormReadWriter{Tx: conn}
		id, err := uuid.GenerateUUID()
		assert.Nil(err)
		user, err := db_test.NewTestUser()
		assert.Nil(err)
		user.Name = "foo-" + id
		err = w.Create(context.Background(), user)
		assert.Nil(err)
		assert.True(user.Id != 0)

		foundUser, err := db_test.NewTestUser()
		assert.Nil(err)
		foundUser.Id = user.Id
		err = w.LookupById(context.Background(), foundUser)
		assert.Nil(err)
		assert.Equal(user.Id, foundUser.Id)

		user.FriendlyName = "friendly-" + id
		err = w.Update(context.Background(), user, []string{"FriendlyName"})
		assert.Nil(err)

		err = w.LookupById(context.Background(), foundUser)
		assert.Nil(err)
		assert.Equal(user.FriendlyName, foundUser.FriendlyName)
	})
	t.Run("valid-WithOplog", func(t *testing.T) {
		w := GormReadWriter{Tx: conn}
		id, err := uuid.GenerateUUID()
		assert.Nil(err)
		user, err := db_test.NewTestUser()
		assert.Nil(err)
		user.Name = "foo-" + id
		err = w.Create(context.Background(), user)
		assert.Nil(err)
		assert.True(user.Id != 0)

		foundUser, err := db_test.NewTestUser()
		assert.Nil(err)
		foundUser.Id = user.Id
		err = w.LookupById(context.Background(), foundUser)
		assert.Nil(err)
		assert.Equal(user.Id, foundUser.Id)

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
		assert.Nil(err)

		err = w.LookupById(context.Background(), foundUser)
		assert.Nil(err)
		assert.Equal(user.FriendlyName, foundUser.FriendlyName)
	})
	t.Run("nil-tx", func(t *testing.T) {
		w := GormReadWriter{Tx: nil}
		id, err := uuid.GenerateUUID()
		assert.Nil(err)
		user, err := db_test.NewTestUser()
		assert.Nil(err)
		user.Name = "foo-" + id
		err = w.Update(context.Background(), user, nil)
		assert.True(err != nil)
		assert.Equal(err.Error(), "update tx is nil")
	})
	t.Run("no-wrapper-WithOplog", func(t *testing.T) {
		w := GormReadWriter{Tx: conn}
		id, err := uuid.GenerateUUID()
		assert.Nil(err)
		user, err := db_test.NewTestUser()
		assert.Nil(err)
		user.Name = "foo-" + id
		err = w.Create(context.Background(), user)
		assert.Nil(err)
		assert.True(user.Id != 0)

		foundUser, err := db_test.NewTestUser()
		assert.Nil(err)
		foundUser.Id = user.Id
		err = w.LookupById(context.Background(), foundUser)
		assert.Nil(err)
		assert.Equal(user.Id, foundUser.Id)

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
		assert.True(err != nil)
		assert.Equal(err.Error(), "error wrapper is nil for WithWrapper")
	})
	t.Run("no-metadata-WithOplog", func(t *testing.T) {
		w := GormReadWriter{Tx: conn}
		id, err := uuid.GenerateUUID()
		assert.Nil(err)
		user, err := db_test.NewTestUser()
		assert.Nil(err)
		user.Name = "foo-" + id
		err = w.Create(context.Background(), user)
		assert.Nil(err)
		assert.True(user.Id != 0)

		foundUser, err := db_test.NewTestUser()
		assert.Nil(err)
		foundUser.Id = user.Id
		err = w.LookupById(context.Background(), foundUser)
		assert.Nil(err)
		assert.Equal(user.Id, foundUser.Id)

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
		assert.True(err != nil)
		assert.Equal(err.Error(), "error no metadata for WithOplog")
	})
}

func TestGormReadWriter_Create(t *testing.T) {
	StartTest()
	t.Parallel()
	cleanup, url := SetupTest(t, "migrations/postgres")
	defer cleanup()
	defer CompleteTest() // must come after the "defer cleanup()"
	conn, err := TestConnection(url)
	assert := assert.New(t)
	assert.Nil(err)
	defer conn.Close()
	t.Run("simple", func(t *testing.T) {
		w := GormReadWriter{Tx: conn}
		id, err := uuid.GenerateUUID()
		assert.Nil(err)
		user, err := db_test.NewTestUser()
		assert.Nil(err)
		user.Name = "foo-" + id
		err = w.Create(context.Background(), user)
		assert.Nil(err)
		assert.True(user.Id != 0)
		assert.True(user.GetCreateTime() != nil)
		assert.True(user.GetUpdateTime() != nil)

		foundUser, err := db_test.NewTestUser()
		assert.Nil(err)
		foundUser.Id = user.Id
		err = w.LookupById(context.Background(), foundUser)
		assert.Nil(err)
		assert.Equal(user.Id, foundUser.Id)
	})
	t.Run("valid-WithOplog", func(t *testing.T) {
		w := GormReadWriter{Tx: conn}
		id, err := uuid.GenerateUUID()
		assert.Nil(err)
		user, err := db_test.NewTestUser()
		assert.Nil(err)
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
		assert.Nil(err)
		assert.True(returnedUser.Id != 0)

		foundUser, err := db_test.NewTestUser()
		assert.Nil(err)
		foundUser.Id = returnedUser.Id
		err = w.LookupById(context.Background(), foundUser)
		assert.Nil(err)
		assert.Equal(returnedUser.Id, foundUser.Id)
	})
	t.Run("no-wrapper-WithOplog", func(t *testing.T) {
		w := GormReadWriter{Tx: conn}
		id, err := uuid.GenerateUUID()
		assert.Nil(err)
		user, err := db_test.NewTestUser()
		assert.Nil(err)
		user.Name = "foo-" + id
		_, err = w.DoTx(
			context.Background(),
			10,
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
		assert.True(err != nil)
		assert.Equal(err.Error(), "error wrapper is nil for WithWrapper")
	})
	t.Run("no-metadata-WithOplog", func(t *testing.T) {
		w := GormReadWriter{Tx: conn}
		id, err := uuid.GenerateUUID()
		assert.Nil(err)
		user, err := db_test.NewTestUser()
		assert.Nil(err)
		user.Name = "foo-" + id
		_, err = w.DoTx(
			context.Background(),
			10,
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
		assert.True(err != nil)
		assert.Equal(err.Error(), "error no metadata for WithOplog")
	})
	t.Run("nil-tx", func(t *testing.T) {
		w := GormReadWriter{Tx: nil}
		id, err := uuid.GenerateUUID()
		assert.Nil(err)
		user, err := db_test.NewTestUser()
		assert.Nil(err)
		user.Name = "foo-" + id
		err = w.Create(context.Background(), user)
		assert.True(err != nil)
		assert.Equal(err.Error(), "create tx is nil")
	})
}

func TestGormReadWriter_LookupByInternalId(t *testing.T) {
	StartTest()
	t.Parallel()
	cleanup, url := SetupTest(t, "migrations/postgres")
	defer cleanup()
	defer CompleteTest() // must come after the "defer cleanup()"
	conn, err := TestConnection(url)
	assert := assert.New(t)
	assert.Nil(err)
	defer conn.Close()
	t.Run("simple", func(t *testing.T) {
		w := GormReadWriter{Tx: conn}
		id, err := uuid.GenerateUUID()
		assert.Nil(err)
		user, err := db_test.NewTestUser()
		assert.Nil(err)
		user.Name = "foo-" + id
		err = w.Create(context.Background(), user)
		assert.Nil(err)
		assert.True(user.Id != 0)

		foundUser, err := db_test.NewTestUser()
		assert.Nil(err)
		foundUser.Id = user.Id
		err = w.LookupById(context.Background(), foundUser)
		assert.Nil(err)
		assert.Equal(user.Id, foundUser.Id)
	})
	t.Run("tx-nil,", func(t *testing.T) {
		w := GormReadWriter{}
		foundUser, err := db_test.NewTestUser()
		assert.Nil(err)
		err = w.LookupById(context.Background(), foundUser)
		assert.True(err != nil)
		assert.Equal(err.Error(), "error tx nil for lookup by internal id")
	})
	t.Run("no-public-id-set", func(t *testing.T) {
		w := GormReadWriter{Tx: conn}
		foundUser, err := db_test.NewTestUser()
		assert.Nil(err)
		err = w.LookupById(context.Background(), foundUser)
		assert.True(err != nil)
		assert.Equal(err.Error(), "error internal id is 0 for lookup by internal id")
	})
	t.Run("not-found", func(t *testing.T) {
		w := GormReadWriter{Tx: conn}
		foundUser, err := db_test.NewTestUser()
		assert.Nil(err)
		foundUser.Id = 4294967295 // we should never get to the max for unit32
		err = w.LookupById(context.Background(), foundUser)
		assert.True(err != nil)
		assert.Equal(err, gorm.ErrRecordNotFound)
	})
}

func TestGormReadWriter_LookupByFriendlyName(t *testing.T) {
	StartTest()
	t.Parallel()
	cleanup, url := SetupTest(t, "migrations/postgres")
	defer cleanup()
	defer CompleteTest() // must come after the "defer cleanup()"
	conn, err := TestConnection(url)
	assert := assert.New(t)
	assert.Nil(err)
	defer conn.Close()
	t.Run("simple", func(t *testing.T) {
		w := GormReadWriter{Tx: conn}
		id, err := uuid.GenerateUUID()
		assert.Nil(err)
		user, err := db_test.NewTestUser()
		assert.Nil(err)
		user.Name = "foo-" + id
		user.FriendlyName = "fn-" + id
		err = w.Create(context.Background(), user)
		assert.Nil(err)
		assert.True(user.Id != 0)

		foundUser, err := db_test.NewTestUser()
		assert.Nil(err)
		foundUser.FriendlyName = "fn-" + id
		err = w.LookupByFriendlyName(context.Background(), foundUser)
		assert.Nil(err)
		assert.Equal(user.Id, foundUser.Id)
	})
	t.Run("tx-nil,", func(t *testing.T) {
		w := GormReadWriter{}
		foundUser, err := db_test.NewTestUser()
		assert.Nil(err)
		foundUser.FriendlyName = "fn-name"
		err = w.LookupByFriendlyName(context.Background(), foundUser)
		assert.True(err != nil)
		assert.Equal(err.Error(), "error tx nil for lookup by friendly name")
	})
	t.Run("no-friendly-name-set", func(t *testing.T) {
		w := GormReadWriter{Tx: conn}
		foundUser, err := db_test.NewTestUser()
		assert.Nil(err)
		err = w.LookupByFriendlyName(context.Background(), foundUser)
		assert.True(err != nil)
		assert.Equal(err.Error(), "error friendly name empty string for lookup by friendly name")
	})
	t.Run("not-found", func(t *testing.T) {
		w := GormReadWriter{Tx: conn}
		id, err := uuid.GenerateUUID()
		assert.Nil(err)

		foundUser, err := db_test.NewTestUser()
		assert.Nil(err)
		foundUser.FriendlyName = "fn-" + id
		err = w.LookupByFriendlyName(context.Background(), foundUser)
		assert.True(err != nil)
		assert.Equal(err, gorm.ErrRecordNotFound)
	})
}

func TestGormReadWriter_LookupByPublicId(t *testing.T) {
	StartTest()
	t.Parallel()
	cleanup, url := SetupTest(t, "migrations/postgres")
	defer cleanup()
	defer CompleteTest() // must come after the "defer cleanup()"
	conn, err := TestConnection(url)
	assert := assert.New(t)
	assert.Nil(err)
	defer conn.Close()
	t.Run("simple", func(t *testing.T) {
		w := GormReadWriter{Tx: conn}
		id, err := uuid.GenerateUUID()
		assert.Nil(err)
		user, err := db_test.NewTestUser()
		assert.Nil(err)
		user.Name = "foo-" + id
		user.FriendlyName = "fn-" + id
		err = w.Create(context.Background(), user)
		assert.Nil(err)
		assert.True(user.PublicId != "")

		foundUser, err := db_test.NewTestUser()
		assert.Nil(err)
		foundUser.PublicId = user.PublicId
		err = w.LookupByPublicId(context.Background(), foundUser)
		assert.Nil(err)
		assert.Equal(user.Id, foundUser.Id)
	})
	t.Run("tx-nil,", func(t *testing.T) {
		w := GormReadWriter{}
		foundUser, err := db_test.NewTestUser()
		assert.Nil(err)
		err = w.LookupByPublicId(context.Background(), foundUser)
		assert.True(err != nil)
		assert.Equal(err.Error(), "error tx nil for lookup by public id")
	})
	t.Run("no-public-id-set", func(t *testing.T) {
		w := GormReadWriter{Tx: conn}
		foundUser, err := db_test.NewTestUser()
		foundUser.PublicId = ""
		assert.Nil(err)
		err = w.LookupByPublicId(context.Background(), foundUser)
		assert.True(err != nil)
		assert.Equal(err.Error(), "error public id empty string for lookup by public id")
	})
	t.Run("not-found", func(t *testing.T) {
		w := GormReadWriter{Tx: conn}
		id, err := uuid.GenerateUUID()
		assert.Nil(err)

		foundUser, err := db_test.NewTestUser()
		assert.Nil(err)
		foundUser.PublicId = id
		err = w.LookupByPublicId(context.Background(), foundUser)
		assert.True(err != nil)
		assert.Equal(err, gorm.ErrRecordNotFound)
	})
}

func TestGormReadWriter_LookupBy(t *testing.T) {
	StartTest()
	t.Parallel()
	cleanup, url := SetupTest(t, "migrations/postgres")
	defer cleanup()
	defer CompleteTest() // must come after the "defer cleanup()"
	conn, err := TestConnection(url)
	assert := assert.New(t)
	assert.Nil(err)
	defer conn.Close()
	t.Run("simple", func(t *testing.T) {
		w := GormReadWriter{Tx: conn}
		id, err := uuid.GenerateUUID()
		assert.Nil(err)
		user, err := db_test.NewTestUser()
		assert.Nil(err)
		user.Name = "foo-" + id
		user.FriendlyName = "fn-" + id
		err = w.Create(context.Background(), user)
		assert.Nil(err)
		assert.True(user.PublicId != "")

		var foundUser db_test.TestUser
		err = w.LookupBy(context.Background(), &foundUser, "public_id = ?", user.PublicId)
		assert.Nil(err)
		assert.Equal(user.Id, foundUser.Id)
	})
	t.Run("tx-nil,", func(t *testing.T) {
		w := GormReadWriter{}
		var foundUser db_test.TestUser
		err = w.LookupBy(context.Background(), &foundUser, "public_id = ?", 1)
		assert.True(err != nil)
		assert.Equal(err.Error(), "error tx nil for lookup by")
	})
	t.Run("not-found", func(t *testing.T) {
		w := GormReadWriter{Tx: conn}
		id, err := uuid.GenerateUUID()
		assert.Nil(err)

		var foundUser db_test.TestUser
		err = w.LookupBy(context.Background(), &foundUser, "public_id = ?", id)
		assert.True(err != nil)
		assert.Equal(err, gorm.ErrRecordNotFound)
	})
	t.Run("bad-where", func(t *testing.T) {
		w := GormReadWriter{Tx: conn}
		id, err := uuid.GenerateUUID()
		assert.Nil(err)

		var foundUser db_test.TestUser
		err = w.LookupBy(context.Background(), &foundUser, "? = ?", id)
		assert.True(err != nil)
	})
}

func TestGormReadWriter_SearchBy(t *testing.T) {
	StartTest()
	t.Parallel()
	cleanup, url := SetupTest(t, "migrations/postgres")
	defer cleanup()
	defer CompleteTest() // must come after the "defer cleanup()"
	conn, err := TestConnection(url)
	assert := assert.New(t)
	assert.Nil(err)
	defer conn.Close()
	t.Run("simple", func(t *testing.T) {
		w := GormReadWriter{Tx: conn}
		id, err := uuid.GenerateUUID()
		assert.Nil(err)
		user, err := db_test.NewTestUser()
		assert.Nil(err)
		user.Name = "foo-" + id
		user.FriendlyName = "fn-" + id
		err = w.Create(context.Background(), user)
		assert.Nil(err)
		assert.True(user.PublicId != "")

		var foundUsers []db_test.TestUser
		err = w.SearchBy(context.Background(), &foundUsers, "public_id = ?", user.PublicId)
		assert.Nil(err)
		assert.Equal(user.Id, foundUsers[0].Id)
	})
	t.Run("tx-nil,", func(t *testing.T) {
		w := GormReadWriter{}
		var foundUsers []db_test.TestUser
		err = w.SearchBy(context.Background(), &foundUsers, "public_id = ?", 1)
		assert.True(err != nil)
		assert.Equal(err.Error(), "error tx nil for search by")
	})
	t.Run("not-found", func(t *testing.T) {
		w := GormReadWriter{Tx: conn}
		id, err := uuid.GenerateUUID()
		assert.Nil(err)

		var foundUsers []db_test.TestUser
		err = w.SearchBy(context.Background(), &foundUsers, "public_id = ?", id)
		assert.Nil(err)
		assert.Equal(len(foundUsers), 0)
	})
	t.Run("bad-where", func(t *testing.T) {
		w := GormReadWriter{Tx: conn}
		id, err := uuid.GenerateUUID()
		assert.Nil(err)

		var foundUsers []db_test.TestUser
		err = w.SearchBy(context.Background(), &foundUsers, "? = ?", id)
		assert.True(err != nil)
	})
}

func TestGormReadWriter_Dialect(t *testing.T) {
	StartTest()
	t.Parallel()
	cleanup, url := SetupTest(t, "migrations/postgres")
	defer cleanup()
	defer CompleteTest() // must come after the "defer cleanup()"
	conn, err := TestConnection(url)
	assert := assert.New(t)
	assert.Nil(err)
	defer conn.Close()
	t.Run("valid", func(t *testing.T) {
		w := GormReadWriter{Tx: conn}
		d, err := w.Dialect()
		assert.Nil(err)
		assert.Equal(d, "postgres")
	})
	t.Run("nil-tx", func(t *testing.T) {
		w := GormReadWriter{Tx: nil}
		d, err := w.Dialect()
		assert.True(err != nil)
		assert.Equal(d, "")
		assert.Equal(err.Error(), "create tx is nil for dialect")
	})
}

func TestGormReadWriter_DB(t *testing.T) {
	StartTest()
	t.Parallel()
	cleanup, url := SetupTest(t, "migrations/postgres")
	defer cleanup()
	defer CompleteTest() // must come after the "defer cleanup()"
	conn, err := TestConnection(url)
	assert := assert.New(t)
	assert.Nil(err)
	defer conn.Close()
	t.Run("valid", func(t *testing.T) {
		w := GormReadWriter{Tx: conn}
		d, err := w.DB()
		assert.Nil(err)
		assert.True(d != nil)
		err = d.Ping()
		assert.Nil(err)
	})
	t.Run("nil-tx", func(t *testing.T) {
		w := GormReadWriter{Tx: nil}
		d, err := w.DB()
		assert.True(err != nil)
		assert.True(d == nil)
		assert.Equal(err.Error(), "create tx is nil for db")
	})
}

func TestGormReadWriter_DoTx(t *testing.T) {
	StartTest()
	t.Parallel()
	cleanup, url := SetupTest(t, "migrations/postgres")
	defer cleanup()
	defer CompleteTest() // must come after the "defer cleanup()"
	conn, err := TestConnection(url)
	assert := assert.New(t)
	assert.Nil(err)
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
		assert.Nil(err)
		assert.Equal(got.Retries, 8)
		assert.Equal(retries, 9) // attempted 1 + 8 retries
	})
	t.Run("zero-retries", func(t *testing.T) {
		w := &GormReadWriter{Tx: conn}
		retries := 0
		got, err := w.DoTx(context.Background(), 0, ExpBackoff{}, func(Writer) error { retries += 1; return nil })
		assert.Nil(err)
		assert.Equal(got, RetryInfo{})
		assert.Equal(retries, 1)
	})
	t.Run("nil-tx", func(t *testing.T) {
		w := &GormReadWriter{nil}
		retries := 0
		got, err := w.DoTx(context.Background(), 1, ExpBackoff{}, func(Writer) error { retries += 1; return nil })
		assert.True(err != nil)
		assert.Equal(got, RetryInfo{})
		assert.Equal(err.Error(), "do tx is nil")
	})
	t.Run("not-a-retry-err", func(t *testing.T) {
		w := &GormReadWriter{Tx: conn}
		got, err := w.DoTx(context.Background(), 1, ExpBackoff{}, func(Writer) error { return errors.New("not a retry error") })
		assert.True(err != nil)
		assert.Equal(got, RetryInfo{})
		assert.True(err != oplog.ErrTicketAlreadyRedeemed)
	})
	t.Run("too-many-retries", func(t *testing.T) {
		w := &GormReadWriter{Tx: conn}
		retries := 0
		got, err := w.DoTx(context.Background(), 2, ExpBackoff{}, func(Writer) error { retries += 1; return oplog.ErrTicketAlreadyRedeemed })
		assert.True(err != nil)
		assert.Equal(got.Retries, 1)
		assert.Equal(err.Error(), "Too many retries: 2 of 2")
	})
}

func TestGormReadWriter_Delete(t *testing.T) {
	StartTest()
	t.Parallel()
	cleanup, url := SetupTest(t, "migrations/postgres")
	defer cleanup()
	defer CompleteTest() // must come after the "defer cleanup()"
	conn, err := TestConnection(url)
	assert := assert.New(t)
	assert.Nil(err)
	defer conn.Close()
	t.Run("simple", func(t *testing.T) {
		w := GormReadWriter{Tx: conn}
		id, err := uuid.GenerateUUID()
		assert.Nil(err)
		user, err := db_test.NewTestUser()
		assert.Nil(err)
		user.Name = "foo-" + id
		err = w.Create(context.Background(), user)
		assert.Nil(err)
		assert.True(user.Id != 0)
		assert.True(user.GetCreateTime() != nil)
		assert.True(user.GetUpdateTime() != nil)

		foundUser, err := db_test.NewTestUser()
		assert.Nil(err)
		foundUser.Id = user.Id
		err = w.LookupById(context.Background(), foundUser)
		assert.Nil(err)
		assert.Equal(user.Id, foundUser.Id)

		err = w.Delete(context.Background(), user)
		assert.Nil(err)

		err = w.LookupById(context.Background(), foundUser)
		assert.True(err != nil)
		assert.Equal(err, gorm.ErrRecordNotFound)
	})
	t.Run("valid-WithOplog", func(t *testing.T) {
		w := GormReadWriter{Tx: conn}
		id, err := uuid.GenerateUUID()
		assert.Nil(err)
		user, err := db_test.NewTestUser()
		assert.Nil(err)
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
		assert.Nil(err)
		assert.True(returnedUser.Id != 0)

		foundUser, err := db_test.NewTestUser()
		assert.Nil(err)
		foundUser.Id = returnedUser.Id
		err = w.LookupById(context.Background(), foundUser)
		assert.Nil(err)
		assert.Equal(returnedUser.Id, foundUser.Id)

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
		assert.Nil(err)

		err = w.LookupById(context.Background(), foundUser)
		assert.True(err != nil)
		assert.Equal(err, gorm.ErrRecordNotFound)
	})
	t.Run("no-wrapper-WithOplog", func(t *testing.T) {
		w := GormReadWriter{Tx: conn}
		id, err := uuid.GenerateUUID()
		assert.Nil(err)
		user, err := db_test.NewTestUser()
		assert.Nil(err)
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
		assert.Nil(err)
		assert.True(returnedUser.Id != 0)

		foundUser, err := db_test.NewTestUser()
		assert.Nil(err)
		foundUser.Id = returnedUser.Id
		err = w.LookupById(context.Background(), foundUser)
		assert.Nil(err)
		assert.Equal(returnedUser.Id, foundUser.Id)

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
		assert.True(err != nil)
		assert.Equal(err.Error(), "error wrapper is nil for WithWrapper")
	})
	t.Run("no-metadata-WithOplog", func(t *testing.T) {
		w := GormReadWriter{Tx: conn}
		id, err := uuid.GenerateUUID()
		assert.Nil(err)
		user, err := db_test.NewTestUser()
		assert.Nil(err)
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
		assert.Nil(err)
		assert.True(returnedUser.Id != 0)

		foundUser, err := db_test.NewTestUser()
		assert.Nil(err)
		foundUser.Id = returnedUser.Id
		err = w.LookupById(context.Background(), foundUser)
		assert.Nil(err)
		assert.Equal(returnedUser.Id, foundUser.Id)

		err = w.Delete(
			context.Background(),
			returnedUser,
			WithOplog(true),
			WithWrapper(InitTestWrapper(t)),
		)
		assert.True(err != nil)
		assert.Equal(err.Error(), "error no metadata for WithOplog")
	})
	t.Run("nil-tx", func(t *testing.T) {
		w := GormReadWriter{Tx: nil}
		id, err := uuid.GenerateUUID()
		assert.Nil(err)
		user, err := db_test.NewTestUser()
		assert.Nil(err)
		user.Name = "foo-" + id
		err = w.Create(context.Background(), user)
		assert.True(err != nil)
		assert.Equal(err.Error(), "create tx is nil")
	})
}

func TestGormReadWriter_ScanRows(t *testing.T) {
	StartTest()
	t.Parallel()
	cleanup, url := SetupTest(t, "migrations/postgres")
	defer cleanup()
	defer CompleteTest() // must come after the "defer cleanup()"
	conn, err := TestConnection(url)
	assert := assert.New(t)
	assert.Nil(err)
	defer conn.Close()
	t.Run("valid", func(t *testing.T) {
		w := GormReadWriter{Tx: conn}
		user, err := db_test.NewTestUser()
		assert.Nil(err)
		err = w.Create(context.Background(), user)
		assert.Nil(err)
		assert.True(user.Id != 0)

		tx, err := w.DB()
		where := "select * from db_test_user where friendly_name in ($1, $2)"
		rows, err := tx.Query(where, "alice", "bob")
		defer rows.Close()
		for rows.Next() {
			u, err := db_test.NewTestUser()
			assert.Nil(err)

			// scan the row into your Gorm struct
			err = w.ScanRows(rows, &u)
			assert.Nil(err)
			assert.Equal(u.PublicId, user.PublicId)
		}
	})
}
