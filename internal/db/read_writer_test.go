package db

import (
	"context"
	"errors"
	"testing"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/watchtower/internal/db/db_test"
	"github.com/hashicorp/watchtower/internal/oplog"
	"github.com/hashicorp/watchtower/internal/oplog/store"
	"github.com/jinzhu/gorm"
	"github.com/stretchr/testify/assert"
)

func TestGormReadWriter_Update(t *testing.T) {
	// intentionally not run with t.Parallel so we don't need to use DoTx for the Update tests
	cleanup, db := SetupTest(t, "migrations/postgres")
	defer cleanup()
	assert := assert.New(t)
	defer db.Close()
	t.Run("simple", func(t *testing.T) {
		w := GormReadWriter{Tx: db}
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
		foundUser.PublicId = user.PublicId
		err = w.LookupByPublicId(context.Background(), foundUser)
		assert.Nil(err)
		assert.Equal(foundUser.Id, user.Id)

		user.FriendlyName = "friendly-" + id
		err = w.Update(context.Background(), user, []string{"FriendlyName"})
		assert.Nil(err)

		err = w.LookupByPublicId(context.Background(), foundUser)
		assert.Nil(err)
		assert.Equal(foundUser.FriendlyName, user.FriendlyName)
	})
	t.Run("valid-WithOplog", func(t *testing.T) {
		w := GormReadWriter{Tx: db}
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
		foundUser.PublicId = user.PublicId
		err = w.LookupByPublicId(context.Background(), foundUser)
		assert.Nil(err)
		assert.Equal(foundUser.Id, user.Id)

		user.FriendlyName = "friendly-" + id
		err = w.Update(context.Background(), user, []string{"FriendlyName"},
			// write oplogs for this update
			WithOplog(
				InitTestWrapper(t),
				oplog.Metadata{
					"key-only":           nil,
					"deployment":         []string{"amex"},
					"project":            []string{"central-info-systems", "local-info-systems"},
					"resource-public-id": []string{user.GetPublicId()},
				}),
		)
		assert.Nil(err)

		err = w.LookupByPublicId(context.Background(), foundUser)
		assert.Nil(err)
		assert.Equal(foundUser.FriendlyName, user.FriendlyName)

		var metadata store.Metadata
		err = db.Where("key = ? and value = ?", "resource-public-id", user.PublicId).First(&metadata).Error
		assert.Nil(err)

		var foundEntry oplog.Entry
		err = db.Where("id = ?", metadata.EntryId).First(&foundEntry).Error
		assert.Nil(err)
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
		assert.Equal("update tx is nil", err.Error())
	})
	t.Run("no-wrapper-WithOplog", func(t *testing.T) {
		w := GormReadWriter{Tx: db}
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
		foundUser.PublicId = user.PublicId
		err = w.LookupByPublicId(context.Background(), foundUser)
		assert.Nil(err)
		assert.Equal(foundUser.Id, user.Id)

		user.FriendlyName = "friendly-" + id
		err = w.Update(context.Background(), user, []string{"FriendlyName"},
			WithOplog(
				nil,
				oplog.Metadata{
					"key-only":   nil,
					"deployment": []string{"amex"},
					"project":    []string{"central-info-systems", "local-info-systems"},
				}),
		)
		assert.True(err != nil)
		assert.Equal("error wrapper is nil for WithWrapper", err.Error())
	})
	t.Run("no-metadata-WithOplog", func(t *testing.T) {
		w := GormReadWriter{Tx: db}
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
		foundUser.PublicId = user.PublicId
		err = w.LookupByPublicId(context.Background(), foundUser)
		assert.Nil(err)
		assert.Equal(foundUser.Id, user.Id)

		user.FriendlyName = "friendly-" + id
		err = w.Update(context.Background(), user, []string{"FriendlyName"},
			WithOplog(
				InitTestWrapper(t),
				nil,
			),
		)
		assert.True(err != nil)
		assert.Equal("error no metadata for WithOplog", err.Error())
	})
}

func TestGormReadWriter_Create(t *testing.T) {
	// intentionally not run with t.Parallel so we don't need to use DoTx for the Create tests
	cleanup, db := SetupTest(t, "migrations/postgres")
	defer cleanup()
	assert := assert.New(t)
	defer db.Close()
	t.Run("simple", func(t *testing.T) {
		w := GormReadWriter{Tx: db}
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
		foundUser.PublicId = user.PublicId
		err = w.LookupByPublicId(context.Background(), foundUser)
		assert.Nil(err)
		assert.Equal(foundUser.Id, user.Id)
	})
	t.Run("valid-WithOplog", func(t *testing.T) {
		w := GormReadWriter{Tx: db}
		id, err := uuid.GenerateUUID()
		assert.Nil(err)
		user, err := db_test.NewTestUser()
		assert.Nil(err)
		user.Name = "foo-" + id
		err = w.Create(
			context.Background(),
			user,
			WithOplog(
				InitTestWrapper(t),
				oplog.Metadata{
					"key-only":   nil,
					"deployment": []string{"amex"},
					"project":    []string{"central-info-systems", "local-info-systems"},
				},
			),
		)
		assert.Nil(err)
		assert.True(user.Id != 0)

		foundUser, err := db_test.NewTestUser()
		assert.Nil(err)
		foundUser.PublicId = user.PublicId
		err = w.LookupByPublicId(context.Background(), foundUser)
		assert.Nil(err)
		assert.Equal(foundUser.Id, user.Id)
	})
	t.Run("no-wrapper-WithOplog", func(t *testing.T) {
		w := GormReadWriter{Tx: db}
		id, err := uuid.GenerateUUID()
		assert.Nil(err)
		user, err := db_test.NewTestUser()
		assert.Nil(err)
		user.Name = "foo-" + id
		err = w.Create(
			context.Background(),
			user,
			WithOplog(
				nil,
				oplog.Metadata{
					"key-only":   nil,
					"deployment": []string{"amex"},
					"project":    []string{"central-info-systems", "local-info-systems"},
				},
			),
		)
		assert.True(err != nil)
		assert.Equal("error wrapper is nil for WithWrapper", err.Error())
	})
	t.Run("no-metadata-WithOplog", func(t *testing.T) {
		w := GormReadWriter{Tx: db}
		id, err := uuid.GenerateUUID()
		assert.Nil(err)
		user, err := db_test.NewTestUser()
		assert.Nil(err)
		user.Name = "foo-" + id
		err = w.Create(
			context.Background(),
			user,
			WithOplog(
				InitTestWrapper(t),
				nil,
			),
		)
		assert.True(err != nil)
		assert.Equal("error no metadata for WithOplog", err.Error())
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
		assert.Equal("create tx is nil", err.Error())
	})
}

func TestGormReadWriter_LookupByFriendlyName(t *testing.T) {
	t.Parallel()
	cleanup, db := SetupTest(t, "migrations/postgres")
	defer cleanup()
	assert := assert.New(t)
	defer db.Close()
	t.Run("simple", func(t *testing.T) {
		w := GormReadWriter{Tx: db}
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
		assert.Equal(foundUser.Id, user.Id)
	})
	t.Run("tx-nil,", func(t *testing.T) {
		w := GormReadWriter{}
		foundUser, err := db_test.NewTestUser()
		assert.Nil(err)
		foundUser.FriendlyName = "fn-name"
		err = w.LookupByFriendlyName(context.Background(), foundUser)
		assert.True(err != nil)
		assert.Equal("error tx nil for lookup by friendly name", err.Error())
	})
	t.Run("no-friendly-name-set", func(t *testing.T) {
		w := GormReadWriter{Tx: db}
		foundUser, err := db_test.NewTestUser()
		assert.Nil(err)
		err = w.LookupByFriendlyName(context.Background(), foundUser)
		assert.True(err != nil)
		assert.Equal("error friendly name empty string for lookup by friendly name", err.Error())
	})
	t.Run("not-found", func(t *testing.T) {
		w := GormReadWriter{Tx: db}
		id, err := uuid.GenerateUUID()
		assert.Nil(err)

		foundUser, err := db_test.NewTestUser()
		assert.Nil(err)
		foundUser.FriendlyName = "fn-" + id
		err = w.LookupByFriendlyName(context.Background(), foundUser)
		assert.True(err != nil)
		assert.Equal(gorm.ErrRecordNotFound, err)
	})
}

func TestGormReadWriter_LookupByPublicId(t *testing.T) {
	t.Parallel()
	cleanup, db := SetupTest(t, "migrations/postgres")
	defer cleanup()
	assert := assert.New(t)
	defer db.Close()
	t.Run("simple", func(t *testing.T) {
		w := GormReadWriter{Tx: db}
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
		assert.Equal(foundUser.Id, user.Id)
	})
	t.Run("tx-nil,", func(t *testing.T) {
		w := GormReadWriter{}
		foundUser, err := db_test.NewTestUser()
		assert.Nil(err)
		err = w.LookupByPublicId(context.Background(), foundUser)
		assert.True(err != nil)
		assert.Equal("error tx nil for lookup by public id", err.Error())
	})
	t.Run("no-public-id-set", func(t *testing.T) {
		w := GormReadWriter{Tx: db}
		foundUser, err := db_test.NewTestUser()
		foundUser.PublicId = ""
		assert.Nil(err)
		err = w.LookupByPublicId(context.Background(), foundUser)
		assert.True(err != nil)
		assert.Equal("error public id empty string for lookup by public id", err.Error())
	})
	t.Run("not-found", func(t *testing.T) {
		w := GormReadWriter{Tx: db}
		id, err := uuid.GenerateUUID()
		assert.Nil(err)

		foundUser, err := db_test.NewTestUser()
		assert.Nil(err)
		foundUser.PublicId = id
		err = w.LookupByPublicId(context.Background(), foundUser)
		assert.True(err != nil)
		assert.Equal(gorm.ErrRecordNotFound, err)
	})
}

func TestGormReadWriter_LookupWhere(t *testing.T) {
	t.Parallel()
	cleanup, db := SetupTest(t, "migrations/postgres")
	defer cleanup()
	assert := assert.New(t)
	defer db.Close()
	t.Run("simple", func(t *testing.T) {
		w := GormReadWriter{Tx: db}
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
		err = w.LookupWhere(context.Background(), &foundUser, "public_id = ?", user.PublicId)
		assert.Nil(err)
		assert.Equal(foundUser.Id, user.Id)
	})
	t.Run("tx-nil,", func(t *testing.T) {
		w := GormReadWriter{}
		var foundUser db_test.TestUser
		err := w.LookupWhere(context.Background(), &foundUser, "public_id = ?", 1)
		assert.True(err != nil)
		assert.Equal("error tx nil for lookup by", err.Error())
	})
	t.Run("not-found", func(t *testing.T) {
		w := GormReadWriter{Tx: db}
		id, err := uuid.GenerateUUID()
		assert.Nil(err)

		var foundUser db_test.TestUser
		err = w.LookupWhere(context.Background(), &foundUser, "public_id = ?", id)
		assert.True(err != nil)
		assert.Equal(gorm.ErrRecordNotFound, err)
	})
	t.Run("bad-where", func(t *testing.T) {
		w := GormReadWriter{Tx: db}
		id, err := uuid.GenerateUUID()
		assert.Nil(err)

		var foundUser db_test.TestUser
		err = w.LookupWhere(context.Background(), &foundUser, "? = ?", id)
		assert.True(err != nil)
	})
}

func TestGormReadWriter_SearchWhere(t *testing.T) {
	t.Parallel()
	cleanup, db := SetupTest(t, "migrations/postgres")
	defer cleanup()
	assert := assert.New(t)
	defer db.Close()
	t.Run("simple", func(t *testing.T) {
		w := GormReadWriter{Tx: db}
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
		err = w.SearchWhere(context.Background(), &foundUsers, "public_id = ?", user.PublicId)
		assert.Nil(err)
		assert.Equal(foundUsers[0].Id, user.Id)
	})
	t.Run("tx-nil,", func(t *testing.T) {
		w := GormReadWriter{}
		var foundUsers []db_test.TestUser
		err := w.SearchWhere(context.Background(), &foundUsers, "public_id = ?", 1)
		assert.True(err != nil)
		assert.Equal("error tx nil for search by", err.Error())
	})
	t.Run("not-found", func(t *testing.T) {
		w := GormReadWriter{Tx: db}
		id, err := uuid.GenerateUUID()
		assert.Nil(err)

		var foundUsers []db_test.TestUser
		err = w.SearchWhere(context.Background(), &foundUsers, "public_id = ?", id)
		assert.Nil(err)
		assert.Equal(0, len(foundUsers))
	})
	t.Run("bad-where", func(t *testing.T) {
		w := GormReadWriter{Tx: db}
		id, err := uuid.GenerateUUID()
		assert.Nil(err)

		var foundUsers []db_test.TestUser
		err = w.SearchWhere(context.Background(), &foundUsers, "? = ?", id)
		assert.True(err != nil)
	})
}

func TestGormReadWriter_DB(t *testing.T) {
	t.Parallel()
	cleanup, db := SetupTest(t, "migrations/postgres")
	defer cleanup()
	assert := assert.New(t)
	defer db.Close()
	t.Run("valid", func(t *testing.T) {
		w := GormReadWriter{Tx: db}
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
		assert.Equal("create tx is nil for db", err.Error())
	})
}

func TestGormReadWriter_DoTx(t *testing.T) {
	t.Parallel()
	cleanup, db := SetupTest(t, "migrations/postgres")
	defer cleanup()
	assert := assert.New(t)
	defer db.Close()

	t.Run("valid-with-10-retries", func(t *testing.T) {
		w := &GormReadWriter{Tx: db}
		attempts := 0
		got, err := w.DoTx(context.Background(), 10, ExpBackoff{},
			func(Writer) error {
				attempts += 1
				if attempts < 9 {
					return oplog.ErrTicketAlreadyRedeemed
				}
				return nil
			})
		assert.Nil(err)
		assert.Equal(8, got.Retries)
		assert.Equal(9, attempts) // attempted 1 + 8 retries
	})
	t.Run("valid-with-1-retries", func(t *testing.T) {
		w := &GormReadWriter{Tx: db}
		attempts := 0
		got, err := w.DoTx(context.Background(), 1, ExpBackoff{},
			func(Writer) error {
				attempts += 1
				if attempts < 2 {
					return oplog.ErrTicketAlreadyRedeemed
				}
				return nil
			})
		assert.Nil(err)
		assert.Equal(1, got.Retries)
		assert.Equal(2, attempts) // attempted 1 + 8 retries
	})
	t.Run("valid-with-2-retries", func(t *testing.T) {
		w := &GormReadWriter{Tx: db}
		attempts := 0
		got, err := w.DoTx(context.Background(), 3, ExpBackoff{},
			func(Writer) error {
				attempts += 1
				if attempts < 3 {
					return oplog.ErrTicketAlreadyRedeemed
				}
				return nil
			})
		assert.Nil(err)
		assert.Equal(2, got.Retries)
		assert.Equal(3, attempts) // attempted 1 + 8 retries
	})
	t.Run("valid-with-4-retries", func(t *testing.T) {
		w := &GormReadWriter{Tx: db}
		attempts := 0
		got, err := w.DoTx(context.Background(), 4, ExpBackoff{},
			func(Writer) error {
				attempts += 1
				if attempts < 4 {
					return oplog.ErrTicketAlreadyRedeemed
				}
				return nil
			})
		assert.Nil(err)
		assert.Equal(3, got.Retries)
		assert.Equal(4, attempts) // attempted 1 + 8 retries
	})
	t.Run("zero-retries", func(t *testing.T) {
		w := &GormReadWriter{Tx: db}
		attempts := 0
		got, err := w.DoTx(context.Background(), 0, ExpBackoff{}, func(Writer) error { attempts += 1; return nil })
		assert.Nil(err)
		assert.Equal(RetryInfo{}, got)
		assert.Equal(1, attempts)
	})
	t.Run("nil-tx", func(t *testing.T) {
		w := &GormReadWriter{nil}
		attempts := 0
		got, err := w.DoTx(context.Background(), 1, ExpBackoff{}, func(Writer) error { attempts += 1; return nil })
		assert.True(err != nil)
		assert.Equal(RetryInfo{}, got)
		assert.Equal("do tx is nil", err.Error())
	})
	t.Run("not-a-retry-err", func(t *testing.T) {
		w := &GormReadWriter{Tx: db}
		got, err := w.DoTx(context.Background(), 1, ExpBackoff{}, func(Writer) error { return errors.New("not a retry error") })
		assert.True(err != nil)
		assert.Equal(RetryInfo{}, got)
		assert.True(err != oplog.ErrTicketAlreadyRedeemed)
	})
	t.Run("too-many-retries", func(t *testing.T) {
		w := &GormReadWriter{Tx: db}
		attempts := 0
		got, err := w.DoTx(context.Background(), 2, ExpBackoff{}, func(Writer) error { attempts += 1; return oplog.ErrTicketAlreadyRedeemed })
		assert.True(err != nil)
		assert.Equal(3, got.Retries)
		assert.Equal("Too many retries: 3 of 3", err.Error())
	})
}

func TestGormReadWriter_Delete(t *testing.T) {
	// intentionally not run with t.Parallel so we don't need to use DoTx for the Create tests
	cleanup, db := SetupTest(t, "migrations/postgres")
	defer cleanup()
	assert := assert.New(t)
	defer db.Close()
	t.Run("simple", func(t *testing.T) {
		w := GormReadWriter{Tx: db}
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
		foundUser.PublicId = user.PublicId
		err = w.LookupByPublicId(context.Background(), foundUser)
		assert.Nil(err)
		assert.Equal(foundUser.Id, user.Id)

		err = w.Delete(context.Background(), user)
		assert.Nil(err)

		err = w.LookupByPublicId(context.Background(), foundUser)
		assert.True(err != nil)
		assert.Equal(gorm.ErrRecordNotFound, err)
	})
	t.Run("valid-WithOplog", func(t *testing.T) {
		w := GormReadWriter{Tx: db}
		id, err := uuid.GenerateUUID()
		assert.Nil(err)
		user, err := db_test.NewTestUser()
		assert.Nil(err)
		user.Name = "foo-" + id
		err = w.Create(
			context.Background(),
			user,
			WithOplog(
				InitTestWrapper(t),
				oplog.Metadata{
					"key-only":   nil,
					"deployment": []string{"amex"},
					"project":    []string{"central-info-systems", "local-info-systems"},
				},
			),
		)
		assert.Nil(err)
		assert.True(user.Id != 0)

		foundUser, err := db_test.NewTestUser()
		assert.Nil(err)
		foundUser.PublicId = user.PublicId
		err = w.LookupByPublicId(context.Background(), foundUser)
		assert.Nil(err)
		assert.Equal(foundUser.Id, user.Id)

		err = w.Delete(
			context.Background(),
			user,
			WithOplog(
				InitTestWrapper(t),
				oplog.Metadata{
					"key-only":   nil,
					"deployment": []string{"amex"},
					"project":    []string{"central-info-systems", "local-info-systems"},
				},
			),
		)
		assert.Nil(err)

		err = w.LookupByPublicId(context.Background(), foundUser)
		assert.True(err != nil)
		assert.Equal(gorm.ErrRecordNotFound, err)
	})
	t.Run("no-wrapper-WithOplog", func(t *testing.T) {
		w := GormReadWriter{Tx: db}
		id, err := uuid.GenerateUUID()
		assert.Nil(err)
		user, err := db_test.NewTestUser()
		assert.Nil(err)
		user.Name = "foo-" + id
		err = w.Create(
			context.Background(),
			user,
			WithOplog(
				InitTestWrapper(t),
				oplog.Metadata{
					"key-only":   nil,
					"deployment": []string{"amex"},
					"project":    []string{"central-info-systems", "local-info-systems"},
				},
			),
		)
		assert.Nil(err)
		assert.True(user.Id != 0)

		foundUser, err := db_test.NewTestUser()
		assert.Nil(err)
		foundUser.PublicId = user.PublicId
		err = w.LookupByPublicId(context.Background(), foundUser)
		assert.Nil(err)
		assert.Equal(foundUser.Id, user.Id)

		err = w.Delete(
			context.Background(),
			user,
			WithOplog(
				nil,
				oplog.Metadata{
					"key-only":   nil,
					"deployment": []string{"amex"},
					"project":    []string{"central-info-systems", "local-info-systems"},
				},
			),
		)
		assert.True(err != nil)
		assert.Equal("error wrapper is nil for WithWrapper", err.Error())
	})
	t.Run("no-metadata-WithOplog", func(t *testing.T) {
		w := GormReadWriter{Tx: db}
		id, err := uuid.GenerateUUID()
		assert.Nil(err)
		user, err := db_test.NewTestUser()
		assert.Nil(err)
		user.Name = "foo-" + id
		err = w.Create(
			context.Background(),
			user,
			WithOplog(
				InitTestWrapper(t),
				oplog.Metadata{
					"key-only":   nil,
					"deployment": []string{"amex"},
					"project":    []string{"central-info-systems", "local-info-systems"},
				},
			),
		)
		assert.Nil(err)
		assert.True(user.Id != 0)

		foundUser, err := db_test.NewTestUser()
		assert.Nil(err)
		foundUser.PublicId = user.PublicId
		err = w.LookupByPublicId(context.Background(), foundUser)
		assert.Nil(err)
		assert.Equal(foundUser.Id, user.Id)

		err = w.Delete(
			context.Background(),
			user,
			WithOplog(
				InitTestWrapper(t),
				nil,
			),
		)
		assert.True(err != nil)
		assert.Equal("error no metadata for WithOplog", err.Error())
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
		assert.Equal("create tx is nil", err.Error())
	})
}

func TestGormReadWriter_ScanRows(t *testing.T) {
	t.Parallel()
	cleanup, db := SetupTest(t, "migrations/postgres")
	defer cleanup()
	assert := assert.New(t)
	defer db.Close()
	t.Run("valid", func(t *testing.T) {
		w := GormReadWriter{Tx: db}
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
			assert.Equal(user.PublicId, u.PublicId)
		}
	})
}
