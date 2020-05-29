package db

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/golang/protobuf/ptypes"
	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/sdk/helper/base62"
	"github.com/hashicorp/watchtower/internal/db/db_test"
	"github.com/hashicorp/watchtower/internal/oplog"
	"github.com/jinzhu/gorm"
	"github.com/stretchr/testify/assert"
)

func TestDb_Update(t *testing.T) {
	cleanup, db, _ := TestSetup(t, "postgres")
	now := &db_test.Timestamp{Timestamp: ptypes.TimestampNow()}
	publicId, err := NewPublicId("testuser")
	if err != nil {
		t.Error(err)
	}
	defer func() {
		if err := cleanup(); err != nil {
			t.Error(err)
		}
	}()
	defer func() {
		if err := db.Close(); err != nil {
			t.Error(err)
		}
	}()
	id := testId(t)
	type args struct {
		i              *db_test.TestUser
		fieldMaskPaths []string
		setToNullPaths []string
		opt            []Option
	}
	tests := []struct {
		name            string
		args            args
		want            int
		wantErr         bool
		wantErrMsg      string
		wantName        string
		wantEmail       string
		wantPhoneNumber string
	}{
		{
			name: "simple",
			args: args{
				i: &db_test.TestUser{
					StoreTestUser: &db_test.StoreTestUser{
						Name:        "simple-updated" + id,
						Email:       "updated" + id,
						PhoneNumber: "updated" + id,
					},
				},
				fieldMaskPaths: []string{"Name", "PhoneNumber"},
				setToNullPaths: []string{"Email"},
			},
			want:            1,
			wantErr:         false,
			wantErrMsg:      "",
			wantName:        "simple-updated" + id,
			wantEmail:       "",
			wantPhoneNumber: "updated" + id,
		},
		{
			name: "multiple-null",
			args: args{
				i: &db_test.TestUser{
					StoreTestUser: &db_test.StoreTestUser{
						Name:        "multiple-null-updated" + id,
						Email:       "updated" + id,
						PhoneNumber: "updated" + id,
					},
				},
				fieldMaskPaths: []string{"Name"},
				setToNullPaths: []string{"Email", "PhoneNumber"},
			},
			want:            1,
			wantErr:         false,
			wantErrMsg:      "",
			wantName:        "multiple-null-updated" + id,
			wantEmail:       "",
			wantPhoneNumber: "",
		},
		{
			name: "non-updatable",
			args: args{
				i: &db_test.TestUser{
					StoreTestUser: &db_test.StoreTestUser{
						Name:        "non-updatable" + id,
						Email:       "updated" + id,
						PhoneNumber: "updated" + id,
						PublicId:    publicId,
						CreateTime:  now,
						UpdateTime:  now,
					},
				},
				fieldMaskPaths: []string{"Name", "PhoneNumber", "CreateTime", "UpdateTime", "PublicId"},
				setToNullPaths: []string{"Email"},
			},
			want:            1,
			wantErr:         false,
			wantErrMsg:      "",
			wantName:        "non-updatable" + id,
			wantEmail:       "",
			wantPhoneNumber: "updated" + id,
		},
		{
			name: "both are missing",
			args: args{
				i: &db_test.TestUser{
					StoreTestUser: &db_test.StoreTestUser{
						Name:        "both are missing-updated" + id,
						Email:       id,
						PhoneNumber: id,
					},
				},
				fieldMaskPaths: nil,
				setToNullPaths: []string{},
			},
			want:       0,
			wantErr:    true,
			wantErrMsg: "update: both fieldMaskPaths and setToNullPaths are missing",
		},
		{
			name: "i is nil",
			args: args{
				i:              nil,
				fieldMaskPaths: []string{"Name", "PhoneNumber"},
				setToNullPaths: []string{"Email"},
			},
			want:       0,
			wantErr:    true,
			wantErrMsg: "update: interface is missing nil parameter",
		},
		{
			name: "only read-only",
			args: args{
				i: &db_test.TestUser{
					StoreTestUser: &db_test.StoreTestUser{
						Name:        "only read-only" + id,
						Email:       id,
						PhoneNumber: id,
					},
				},
				fieldMaskPaths: []string{"CreateTime"},
				setToNullPaths: []string{"UpdateTime"},
			},
			want:       0,
			wantErr:    true,
			wantErrMsg: "update: after filtering non-updated fields, there are no fields left in fieldMaskPaths or setToNullPaths",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			rw := &Db{
				underlying: db,
			}
			u := testUser(t, db, tt.name+id, id, id)

			if tt.args.i != nil {
				tt.args.i.Id = u.Id
				tt.args.i.PublicId = u.PublicId
			}
			rowsUpdated, err := rw.Update(context.Background(), tt.args.i, tt.args.fieldMaskPaths, tt.args.setToNullPaths, tt.args.opt...)
			// if err == nil && tt.wantErr {
			// 	assert.Error(err)
			// }
			if tt.wantErr {
				assert.Error(err)
				assert.Equal(tt.want, rowsUpdated)
				assert.Equal(tt.wantErrMsg, err.Error())
				return
			}
			assert.NoError(err)
			assert.Equal(tt.want, rowsUpdated)

			foundUser, err := db_test.NewTestUser()
			assert.NoError(err)
			foundUser.PublicId = tt.args.i.PublicId
			where := "public_id = ?"
			for _, f := range tt.args.setToNullPaths {
				switch {
				case strings.EqualFold(f, "phonenumber"):
					f = "phone_number"
				}
				where = fmt.Sprintf("%s and %s is null", where, f)
			}
			err = rw.LookupWhere(context.Background(), foundUser, where, tt.args.i.PublicId)
			assert.NoError(err)
			assert.Equal(tt.args.i.Id, foundUser.Id)
			assert.Equal(tt.wantName, foundUser.Name)
			assert.Equal(tt.wantEmail, foundUser.Email)
			assert.Equal(tt.wantPhoneNumber, foundUser.PhoneNumber)
			assert.NotEqual(now, foundUser.CreateTime)
			assert.NotEqual(now, foundUser.UpdateTime)
			assert.NotEqual(publicId, foundUser.PublicId)
		})
	}

	assert := assert.New(t)
	t.Run("valid-WithOplog", func(t *testing.T) {
		w := Db{underlying: db}
		id, err := uuid.GenerateUUID()
		assert.NoError(err)
		user := testUser(t, db, "foo-"+id, id, id)

		user.Name = "friendly-" + id
		rowsUpdated, err := w.Update(context.Background(), user, []string{"Name"}, nil,
			// write oplogs for this update
			WithOplog(
				TestWrapper(t),
				oplog.Metadata{
					"key-only":           nil,
					"deployment":         []string{"amex"},
					"project":            []string{"central-info-systems", "local-info-systems"},
					"resource-public-id": []string{user.PublicId},
					"op-type":            []string{oplog.OpType_OP_TYPE_UPDATE.String()},
				}),
		)
		assert.NoError(err)
		assert.Equal(1, rowsUpdated)

		foundUser, err := db_test.NewTestUser()
		assert.NoError(err)
		foundUser.PublicId = user.PublicId
		err = w.LookupByPublicId(context.Background(), foundUser)
		assert.NoError(err)
		assert.Equal(foundUser.Name, user.Name)

		err = TestVerifyOplog(t, &w, user.PublicId, WithOperation(oplog.OpType_OP_TYPE_UPDATE), WithCreateNotBefore(10*time.Second))
		assert.NoError(err)
	})
	t.Run("vet-for-write", func(t *testing.T) {
		w := Db{underlying: db}
		id, err := uuid.GenerateUUID()
		assert.NoError(err)
		user := &testUserWithVet{
			PublicId:    id,
			Name:        id,
			PhoneNumber: id,
			Email:       id,
		}
		err = db.Create(user).Error
		assert.NoError(err)

		user.Name = "friendly-" + id
		rowsUpdated, err := w.Update(context.Background(), user, []string{"Name"}, nil)
		assert.NoError(err)
		assert.Equal(1, rowsUpdated)

		foundUser := &testUserWithVet{PublicId: user.PublicId}
		assert.NoError(err)
		foundUser.PublicId = user.PublicId
		err = w.LookupByPublicId(context.Background(), foundUser)
		assert.NoError(err)
		assert.Equal(foundUser.Name, user.Name)

		user.PublicId = "not-allowed-by-vet-for-write"
		rowsUpdated, err = w.Update(context.Background(), user, []string{"PublicId"}, nil)
		assert.Error(err)
		assert.Equal(0, rowsUpdated)
	})
	t.Run("nil-tx", func(t *testing.T) {
		w := Db{underlying: nil}
		id, err := uuid.GenerateUUID()
		assert.NoError(err)

		user := testUser(t, db, "foo-"+id, id, id)
		rowsUpdated, err := w.Update(context.Background(), user, []string{"Name"}, nil)
		assert.Error(err)
		assert.Equal(0, rowsUpdated)
		assert.Equal("update: missing underlying db nil parameter", err.Error())
	})
	t.Run("no-wrapper-WithOplog", func(t *testing.T) {
		w := Db{underlying: db}
		id, err := uuid.GenerateUUID()
		assert.NoError(err)
		user := testUser(t, db, "foo-"+id, id, id)

		user.Name = "friendly-" + id
		rowsUpdated, err := w.Update(context.Background(), user, []string{"Name"},
			nil,
			WithOplog(
				nil,
				oplog.Metadata{
					"key-only":   nil,
					"deployment": []string{"amex"},
					"project":    []string{"central-info-systems", "local-info-systems"},
				}),
		)
		assert.Error(err)
		assert.Equal(0, rowsUpdated)
		assert.Equal("update: oplog validation failed error no wrapper WithOplog", err.Error())
	})
	t.Run("no-metadata-WithOplog", func(t *testing.T) {
		w := Db{underlying: db}
		id, err := uuid.GenerateUUID()
		assert.NoError(err)
		user := testUser(t, db, "foo-"+id, id, id)
		user.Name = "friendly-" + id
		rowsUpdated, err := w.Update(context.Background(), user, []string{"Name"}, nil,
			WithOplog(
				TestWrapper(t),
				nil,
			),
		)
		assert.Error(err)
		assert.Equal(0, rowsUpdated)
		assert.Equal("update: oplog validation failed error no metadata for WithOplog", err.Error())
	})
}

// testUserWithVet gives us a model that implements VetForWrite() without any
// cyclic dependencies.
type testUserWithVet struct {
	Id          uint32 `gorm:"primary_key"`
	PublicId    string
	Name        string `gorm:"default:null"`
	PhoneNumber string `gorm:"default:null"`
	Email       string `gorm:"default:null"`
}

func (u *testUserWithVet) GetPublicId() string {
	return u.PublicId
}
func (u *testUserWithVet) TableName() string {
	return "db_test_user"
}
func (u *testUserWithVet) VetForWrite(ctx context.Context, r Reader, opType OpType, opt ...Option) error {
	if u.PublicId == "" {
		return errors.New("public id is empty string for user write")
	}
	if opType == UpdateOp {
		dbOptions := GetOpts(opt...)
		for _, path := range dbOptions.WithFieldMaskPaths {
			switch path {
			case "PublicId":
				return errors.New("you cannot change the public id")
			}
		}
	}
	if opType == CreateOp {
		if u.Id != 0 {
			return errors.New("id is a db sequence")
		}
	}
	return nil
}

func TestDb_Create(t *testing.T) {
	// intentionally not run with t.Parallel so we don't need to use DoTx for the Create tests
	cleanup, db, _ := TestSetup(t, "postgres")
	defer func() {
		if err := cleanup(); err != nil {
			t.Error(err)
		}
	}()
	assert := assert.New(t)
	defer db.Close()
	t.Run("simple", func(t *testing.T) {
		w := Db{underlying: db}
		id, err := uuid.GenerateUUID()
		assert.NoError(err)
		user, err := db_test.NewTestUser()
		assert.NoError(err)
		ts := &db_test.Timestamp{Timestamp: ptypes.TimestampNow()}
		user.CreateTime = ts
		user.UpdateTime = ts
		user.Name = "foo-" + id
		err = w.Create(context.Background(), user)
		assert.NoError(err)
		assert.NotEmpty(user.Id)
		// make sure the database controlled the timestamp values
		assert.NotEqual(ts, user.GetCreateTime())
		assert.NotEqual(ts, user.GetUpdateTime())

		foundUser, err := db_test.NewTestUser()
		assert.NoError(err)
		foundUser.PublicId = user.PublicId
		err = w.LookupByPublicId(context.Background(), foundUser)
		assert.NoError(err)
		assert.Equal(foundUser.Id, user.Id)
	})
	t.Run("valid-WithOplog", func(t *testing.T) {
		w := Db{underlying: db}
		id, err := uuid.GenerateUUID()
		assert.NoError(err)
		user, err := db_test.NewTestUser()
		assert.NoError(err)
		user.Name = "foo-" + id
		err = w.Create(
			context.Background(),
			user,
			WithOplog(
				TestWrapper(t),
				oplog.Metadata{
					"key-only":   nil,
					"deployment": []string{"amex"},
					"project":    []string{"central-info-systems", "local-info-systems"},
				},
			),
		)
		assert.NoError(err)
		assert.NotEmpty(user.Id)

		foundUser, err := db_test.NewTestUser()
		assert.NoError(err)
		foundUser.PublicId = user.PublicId
		err = w.LookupByPublicId(context.Background(), foundUser)
		assert.NoError(err)
		assert.Equal(foundUser.Id, user.Id)
	})
	t.Run("no-wrapper-WithOplog", func(t *testing.T) {
		w := Db{underlying: db}
		id, err := uuid.GenerateUUID()
		assert.NoError(err)
		user, err := db_test.NewTestUser()
		assert.NoError(err)
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
		assert.Error(err)
		assert.Equal("create: oplog validation failed error no wrapper WithOplog", err.Error())
	})
	t.Run("no-metadata-WithOplog", func(t *testing.T) {
		w := Db{underlying: db}
		id, err := uuid.GenerateUUID()
		assert.NoError(err)
		user, err := db_test.NewTestUser()
		assert.NoError(err)
		user.Name = "foo-" + id
		err = w.Create(
			context.Background(),
			user,
			WithOplog(
				TestWrapper(t),
				nil,
			),
		)
		assert.Error(err)
		assert.Equal("create: oplog validation failed error no metadata for WithOplog", err.Error())
	})
	t.Run("nil-tx", func(t *testing.T) {
		w := Db{underlying: nil}
		id, err := uuid.GenerateUUID()
		assert.NoError(err)
		user, err := db_test.NewTestUser()
		assert.NoError(err)
		user.Name = "foo-" + id
		err = w.Create(context.Background(), user)
		assert.Error(err)
		assert.Equal("create: missing underlying db nil parameter", err.Error())
	})
}

func TestDb_LookupByName(t *testing.T) {
	t.Parallel()
	cleanup, db, _ := TestSetup(t, "postgres")
	defer func() {
		if err := cleanup(); err != nil {
			t.Error(err)
		}
	}()
	assert := assert.New(t)
	defer db.Close()
	t.Run("simple", func(t *testing.T) {
		w := Db{underlying: db}
		id, err := uuid.GenerateUUID()
		assert.NoError(err)
		user, err := db_test.NewTestUser()
		assert.NoError(err)
		user.Name = "fn-" + id
		err = w.Create(context.Background(), user)
		assert.NoError(err)
		assert.NotEmpty(user.Id)

		foundUser, err := db_test.NewTestUser()
		assert.NoError(err)
		foundUser.Name = "fn-" + id
		err = w.LookupByName(context.Background(), foundUser)
		assert.NoError(err)
		assert.Equal(foundUser.Id, user.Id)
	})
	t.Run("tx-nil,", func(t *testing.T) {
		w := Db{}
		foundUser, err := db_test.NewTestUser()
		assert.NoError(err)
		foundUser.Name = "fn-name"
		err = w.LookupByName(context.Background(), foundUser)
		assert.Error(err)
		assert.Equal("error underlying db nil for lookup by name", err.Error())
	})
	t.Run("no-friendly-name-set", func(t *testing.T) {
		w := Db{underlying: db}
		foundUser, err := db_test.NewTestUser()
		assert.NoError(err)
		err = w.LookupByName(context.Background(), foundUser)
		assert.Error(err)
		assert.Equal("error name empty string for lookup by name", err.Error())
	})
	t.Run("not-found", func(t *testing.T) {
		w := Db{underlying: db}
		id, err := uuid.GenerateUUID()
		assert.NoError(err)

		foundUser, err := db_test.NewTestUser()
		assert.NoError(err)
		foundUser.Name = "fn-" + id
		err = w.LookupByName(context.Background(), foundUser)
		assert.Error(err)
		assert.Equal(ErrRecordNotFound, err)
	})
}

func TestDb_LookupByPublicId(t *testing.T) {
	t.Parallel()
	cleanup, db, _ := TestSetup(t, "postgres")
	defer func() {
		if err := cleanup(); err != nil {
			t.Error(err)
		}
	}()
	assert := assert.New(t)
	defer db.Close()
	t.Run("simple", func(t *testing.T) {
		w := Db{underlying: db}
		id, err := uuid.GenerateUUID()
		assert.NoError(err)
		user, err := db_test.NewTestUser()
		assert.NoError(err)
		user.Name = "foo-" + id
		err = w.Create(context.Background(), user)
		assert.NoError(err)
		assert.NotEmpty(user.PublicId)

		foundUser, err := db_test.NewTestUser()
		assert.NoError(err)
		foundUser.PublicId = user.PublicId
		err = w.LookupByPublicId(context.Background(), foundUser)
		assert.NoError(err)
		assert.Equal(foundUser.Id, user.Id)
	})
	t.Run("tx-nil,", func(t *testing.T) {
		w := Db{}
		foundUser, err := db_test.NewTestUser()
		assert.NoError(err)
		err = w.LookupByPublicId(context.Background(), foundUser)
		assert.Error(err)
		assert.Equal("error underlying db nil for lookup by public id", err.Error())
	})
	t.Run("no-public-id-set", func(t *testing.T) {
		w := Db{underlying: db}
		foundUser, err := db_test.NewTestUser()
		foundUser.PublicId = ""
		assert.NoError(err)
		err = w.LookupByPublicId(context.Background(), foundUser)
		assert.Error(err)
		assert.Equal("error public id empty string for lookup by public id", err.Error())
	})
	t.Run("not-found", func(t *testing.T) {
		w := Db{underlying: db}
		id, err := uuid.GenerateUUID()
		assert.NoError(err)

		foundUser, err := db_test.NewTestUser()
		assert.NoError(err)
		foundUser.PublicId = id
		err = w.LookupByPublicId(context.Background(), foundUser)
		assert.Error(err)
		assert.Equal(ErrRecordNotFound, err)
	})
}

func TestDb_LookupWhere(t *testing.T) {
	t.Parallel()
	cleanup, db, _ := TestSetup(t, "postgres")
	defer func() {
		if err := cleanup(); err != nil {
			t.Error(err)
		}
	}()
	assert := assert.New(t)
	defer db.Close()
	t.Run("simple", func(t *testing.T) {
		w := Db{underlying: db}
		id, err := uuid.GenerateUUID()
		assert.NoError(err)
		user, err := db_test.NewTestUser()
		assert.NoError(err)
		user.Name = "foo-" + id
		err = w.Create(context.Background(), user)
		assert.NoError(err)
		assert.NotEmpty(user.PublicId)

		var foundUser db_test.TestUser
		err = w.LookupWhere(context.Background(), &foundUser, "public_id = ?", user.PublicId)
		assert.NoError(err)
		assert.Equal(foundUser.Id, user.Id)
	})
	t.Run("tx-nil,", func(t *testing.T) {
		w := Db{}
		var foundUser db_test.TestUser
		err := w.LookupWhere(context.Background(), &foundUser, "public_id = ?", 1)
		assert.Error(err)
		assert.Equal("error underlying db nil for lookup by", err.Error())
	})
	t.Run("not-found", func(t *testing.T) {
		w := Db{underlying: db}
		id, err := uuid.GenerateUUID()
		assert.NoError(err)

		var foundUser db_test.TestUser
		err = w.LookupWhere(context.Background(), &foundUser, "public_id = ?", id)
		assert.Error(err)
		assert.Equal(ErrRecordNotFound, err)
		assert.True(errors.Is(err, ErrRecordNotFound))
	})
	t.Run("bad-where", func(t *testing.T) {
		w := Db{underlying: db}
		id, err := uuid.GenerateUUID()
		assert.NoError(err)

		var foundUser db_test.TestUser
		err = w.LookupWhere(context.Background(), &foundUser, "? = ?", id)
		assert.Error(err)
	})
}

func TestDb_SearchWhere(t *testing.T) {
	t.Parallel()
	cleanup, db, _ := TestSetup(t, "postgres")
	defer func() {
		if err := cleanup(); err != nil {
			t.Error(err)
		}
	}()
	assert := assert.New(t)
	defer db.Close()
	t.Run("simple", func(t *testing.T) {
		w := Db{underlying: db}
		id, err := uuid.GenerateUUID()
		assert.NoError(err)
		user, err := db_test.NewTestUser()
		assert.NoError(err)
		user.Name = "foo-" + id
		err = w.Create(context.Background(), user)
		assert.NoError(err)
		assert.NotEmpty(user.PublicId)

		var foundUsers []db_test.TestUser
		err = w.SearchWhere(context.Background(), &foundUsers, "public_id = ?", user.PublicId)
		assert.NoError(err)
		assert.Equal(foundUsers[0].Id, user.Id)
	})
	t.Run("tx-nil,", func(t *testing.T) {
		w := Db{}
		var foundUsers []db_test.TestUser
		err := w.SearchWhere(context.Background(), &foundUsers, "public_id = ?", 1)
		assert.Error(err)
		assert.Equal("error underlying db nil for search by", err.Error())
	})
	t.Run("not-found", func(t *testing.T) {
		w := Db{underlying: db}
		id, err := uuid.GenerateUUID()
		assert.NoError(err)

		var foundUsers []db_test.TestUser
		err = w.SearchWhere(context.Background(), &foundUsers, "public_id = ?", id)
		assert.NoError(err)
		assert.Equal(0, len(foundUsers))
	})
	t.Run("bad-where", func(t *testing.T) {
		w := Db{underlying: db}
		id, err := uuid.GenerateUUID()
		assert.NoError(err)

		var foundUsers []db_test.TestUser
		err = w.SearchWhere(context.Background(), &foundUsers, "? = ?", id)
		assert.Error(err)
	})
}

func TestDb_DB(t *testing.T) {
	t.Parallel()
	cleanup, db, _ := TestSetup(t, "postgres")
	defer func() {
		if err := cleanup(); err != nil {
			t.Error(err)
		}
	}()
	assert := assert.New(t)
	defer db.Close()
	t.Run("valid", func(t *testing.T) {
		w := Db{underlying: db}
		d, err := w.DB()
		assert.NoError(err)
		assert.NotNil(d)
		err = d.Ping()
		assert.NoError(err)
	})
	t.Run("nil-tx", func(t *testing.T) {
		w := Db{underlying: nil}
		d, err := w.DB()
		assert.Error(err)
		assert.Nil(d)
		assert.Equal("missing underlying db: nil parameter", err.Error())
	})
}

func TestDb_DoTx(t *testing.T) {
	t.Parallel()
	cleanup, db, _ := TestSetup(t, "postgres")
	defer func() {
		if err := cleanup(); err != nil {
			t.Error(err)
		}
	}()
	assert := assert.New(t)
	defer db.Close()

	t.Run("valid-with-10-retries", func(t *testing.T) {
		w := &Db{underlying: db}
		attempts := 0
		got, err := w.DoTx(context.Background(), 10, ExpBackoff{},
			func(Writer) error {
				attempts += 1
				if attempts < 9 {
					return oplog.ErrTicketAlreadyRedeemed
				}
				return nil
			})
		assert.NoError(err)
		assert.Equal(8, got.Retries)
		assert.Equal(9, attempts) // attempted 1 + 8 retries
	})
	t.Run("valid-with-1-retries", func(t *testing.T) {
		w := &Db{underlying: db}
		attempts := 0
		got, err := w.DoTx(context.Background(), 1, ExpBackoff{},
			func(Writer) error {
				attempts += 1
				if attempts < 2 {
					return oplog.ErrTicketAlreadyRedeemed
				}
				return nil
			})
		assert.NoError(err)
		assert.Equal(1, got.Retries)
		assert.Equal(2, attempts) // attempted 1 + 8 retries
	})
	t.Run("valid-with-2-retries", func(t *testing.T) {
		w := &Db{underlying: db}
		attempts := 0
		got, err := w.DoTx(context.Background(), 3, ExpBackoff{},
			func(Writer) error {
				attempts += 1
				if attempts < 3 {
					return oplog.ErrTicketAlreadyRedeemed
				}
				return nil
			})
		assert.NoError(err)
		assert.Equal(2, got.Retries)
		assert.Equal(3, attempts) // attempted 1 + 8 retries
	})
	t.Run("valid-with-4-retries", func(t *testing.T) {
		w := &Db{underlying: db}
		attempts := 0
		got, err := w.DoTx(context.Background(), 4, ExpBackoff{},
			func(Writer) error {
				attempts += 1
				if attempts < 4 {
					return oplog.ErrTicketAlreadyRedeemed
				}
				return nil
			})
		assert.NoError(err)
		assert.Equal(3, got.Retries)
		assert.Equal(4, attempts) // attempted 1 + 8 retries
	})
	t.Run("zero-retries", func(t *testing.T) {
		w := &Db{underlying: db}
		attempts := 0
		got, err := w.DoTx(context.Background(), 0, ExpBackoff{}, func(Writer) error { attempts += 1; return nil })
		assert.NoError(err)
		assert.Equal(RetryInfo{}, got)
		assert.Equal(1, attempts)
	})
	t.Run("nil-tx", func(t *testing.T) {
		w := &Db{nil}
		attempts := 0
		got, err := w.DoTx(context.Background(), 1, ExpBackoff{}, func(Writer) error { attempts += 1; return nil })
		assert.Error(err)
		assert.Equal(RetryInfo{}, got)
		assert.Equal("do underlying db is nil", err.Error())
	})
	t.Run("not-a-retry-err", func(t *testing.T) {
		w := &Db{underlying: db}
		got, err := w.DoTx(context.Background(), 1, ExpBackoff{}, func(Writer) error { return errors.New("not a retry error") })
		assert.Error(err)
		assert.Equal(RetryInfo{}, got)
		assert.NotEqual(err, oplog.ErrTicketAlreadyRedeemed)
	})
	t.Run("too-many-retries", func(t *testing.T) {
		w := &Db{underlying: db}
		attempts := 0
		got, err := w.DoTx(context.Background(), 2, ExpBackoff{}, func(Writer) error { attempts += 1; return oplog.ErrTicketAlreadyRedeemed })
		assert.Error(err)
		assert.Equal(3, got.Retries)
		assert.Equal("Too many retries: 3 of 3", err.Error())
	})
	t.Run("updating-good-bad-good", func(t *testing.T) {
		w := Db{underlying: db}
		id, err := uuid.GenerateUUID()
		assert.NoError(err)
		user, err := db_test.NewTestUser()
		assert.NoError(err)
		user.Name = "foo-" + id
		err = w.Create(context.Background(), user)
		assert.NoError(err)
		assert.NotZero(user.Id)

		_, err = w.DoTx(context.Background(), 10, ExpBackoff{}, func(w Writer) error {
			user.Name = "friendly-" + id
			rowsUpdated, err := w.Update(context.Background(), user, []string{"Name"}, nil)
			if err != nil {
				return err
			}
			if rowsUpdated != 1 {
				return fmt.Errorf("error in number of rows updated %d", rowsUpdated)
			}
			return nil
		})
		assert.NoError(err)

		foundUser, err := db_test.NewTestUser()
		assert.NoError(err)
		foundUser.PublicId = user.PublicId
		err = w.LookupByPublicId(context.Background(), foundUser)
		assert.NoError(err)
		assert.Equal(foundUser.Name, user.Name)

		user2, err := db_test.NewTestUser()
		assert.NoError(err)
		_, err = w.DoTx(context.Background(), 10, ExpBackoff{}, func(w Writer) error {
			user2.Name = "friendly2-" + id
			rowsUpdated, err := w.Update(context.Background(), user2, []string{"Name"}, nil)
			if err != nil {
				return err
			}
			if rowsUpdated != 1 {
				return fmt.Errorf("error in number of rows updated %d", rowsUpdated)
			}
			return nil
		})
		assert.Error(err)
		err = w.LookupByPublicId(context.Background(), foundUser)
		assert.NoError(err)
		assert.NotEqual(foundUser.Name, user2.Name)

		_, err = w.DoTx(context.Background(), 10, ExpBackoff{}, func(w Writer) error {
			user.Name = "friendly2-" + id
			rowsUpdated, err := w.Update(context.Background(), user, []string{"Name"}, nil)
			if err != nil {
				return err
			}
			if rowsUpdated != 1 {
				return fmt.Errorf("error in number of rows updated %d", rowsUpdated)
			}
			return nil
		})
		assert.NoError(err)
		err = w.LookupByPublicId(context.Background(), foundUser)
		assert.NoError(err)
		assert.Equal(foundUser.Name, user.Name)
	})
}

func TestDb_Delete(t *testing.T) {
	// intentionally not run with t.Parallel so we don't need to use DoTx for the Create tests
	cleanup, db, _ := TestSetup(t, "postgres")
	defer func() {
		if err := cleanup(); err != nil {
			t.Error(err)
		}
	}()
	assert := assert.New(t)
	defer db.Close()
	t.Run("simple", func(t *testing.T) {
		w := Db{underlying: db}
		id, err := uuid.GenerateUUID()
		assert.NoError(err)
		user, err := db_test.NewTestUser()
		assert.NoError(err)
		user.Name = "foo-" + id
		err = w.Create(context.Background(), user)
		assert.NoError(err)
		assert.NotEmpty(user.Id)
		assert.NotNil(user.GetCreateTime())
		assert.NotNil(user.GetUpdateTime())

		foundUser, err := db_test.NewTestUser()
		assert.NoError(err)
		foundUser.PublicId = user.PublicId
		err = w.LookupByPublicId(context.Background(), foundUser)
		assert.NoError(err)
		assert.Equal(foundUser.Id, user.Id)

		rowsDeleted, err := w.Delete(context.Background(), user)
		assert.NoError(err)
		assert.Equal(1, rowsDeleted)

		err = w.LookupByPublicId(context.Background(), foundUser)
		assert.Error(err)
		assert.Equal(ErrRecordNotFound, err)
	})
	t.Run("valid-WithOplog", func(t *testing.T) {
		w := Db{underlying: db}
		id, err := uuid.GenerateUUID()
		assert.NoError(err)
		user, err := db_test.NewTestUser()
		assert.NoError(err)
		user.Name = "foo-" + id
		err = w.Create(
			context.Background(),
			user,
			WithOplog(
				TestWrapper(t),
				oplog.Metadata{
					"key-only":   nil,
					"deployment": []string{"amex"},
					"project":    []string{"central-info-systems", "local-info-systems"},
				},
			),
		)
		assert.NoError(err)
		assert.NotEmpty(user.Id)

		foundUser, err := db_test.NewTestUser()
		assert.NoError(err)
		foundUser.PublicId = user.PublicId
		err = w.LookupByPublicId(context.Background(), foundUser)
		assert.NoError(err)
		assert.Equal(foundUser.Id, user.Id)

		rowsDeleted, err := w.Delete(
			context.Background(),
			user,
			WithOplog(
				TestWrapper(t),
				oplog.Metadata{
					"key-only":   nil,
					"deployment": []string{"amex"},
					"project":    []string{"central-info-systems", "local-info-systems"},
				},
			),
		)
		assert.NoError(err)
		assert.Equal(1, rowsDeleted)

		err = w.LookupByPublicId(context.Background(), foundUser)
		assert.Error(err)
		assert.Equal(ErrRecordNotFound, err)
	})
	t.Run("no-wrapper-WithOplog", func(t *testing.T) {
		w := Db{underlying: db}
		id, err := uuid.GenerateUUID()
		assert.NoError(err)
		user, err := db_test.NewTestUser()
		assert.NoError(err)
		user.Name = "foo-" + id
		err = w.Create(
			context.Background(),
			user,
			WithOplog(
				TestWrapper(t),
				oplog.Metadata{
					"key-only":   nil,
					"deployment": []string{"amex"},
					"project":    []string{"central-info-systems", "local-info-systems"},
				},
			),
		)
		assert.NoError(err)
		assert.NotEmpty(user.Id)

		foundUser, err := db_test.NewTestUser()
		assert.NoError(err)
		foundUser.PublicId = user.PublicId
		err = w.LookupByPublicId(context.Background(), foundUser)
		assert.NoError(err)
		assert.Equal(foundUser.Id, user.Id)

		rowsDeleted, err := w.Delete(
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
		assert.Error(err)
		assert.Equal(0, rowsDeleted)
		assert.Equal("delete: oplog validation failed error no wrapper WithOplog", err.Error())
	})
	t.Run("no-metadata-WithOplog", func(t *testing.T) {
		w := Db{underlying: db}
		id, err := uuid.GenerateUUID()
		assert.NoError(err)
		user, err := db_test.NewTestUser()
		assert.NoError(err)
		user.Name = "foo-" + id
		err = w.Create(
			context.Background(),
			user,
			WithOplog(
				TestWrapper(t),
				oplog.Metadata{
					"key-only":   nil,
					"deployment": []string{"amex"},
					"project":    []string{"central-info-systems", "local-info-systems"},
				},
			),
		)
		assert.NoError(err)
		assert.NotEmpty(user.Id)

		foundUser, err := db_test.NewTestUser()
		assert.NoError(err)
		foundUser.PublicId = user.PublicId
		err = w.LookupByPublicId(context.Background(), foundUser)
		assert.NoError(err)
		assert.Equal(foundUser.Id, user.Id)

		rowsDeleted, err := w.Delete(
			context.Background(),
			user,
			WithOplog(
				TestWrapper(t),
				nil,
			),
		)
		assert.Error(err)
		assert.Equal(0, rowsDeleted)
		assert.Equal("delete: oplog validation failed error no metadata for WithOplog", err.Error())
	})
	t.Run("nil-tx", func(t *testing.T) {
		w := Db{underlying: nil}
		id, err := uuid.GenerateUUID()
		assert.NoError(err)
		user, err := db_test.NewTestUser()
		assert.NoError(err)
		user.Name = "foo-" + id
		err = w.Create(context.Background(), user)
		assert.Error(err)
		assert.Equal("create: missing underlying db nil parameter", err.Error())
	})
}

func TestDb_ScanRows(t *testing.T) {
	t.Parallel()
	cleanup, db, _ := TestSetup(t, "postgres")
	defer func() {
		if err := cleanup(); err != nil {
			t.Error(err)
		}
	}()
	assert := assert.New(t)
	defer db.Close()
	t.Run("valid", func(t *testing.T) {
		w := Db{underlying: db}
		user, err := db_test.NewTestUser()
		assert.NoError(err)
		err = w.Create(context.Background(), user)
		assert.NoError(err)
		assert.NotEmpty(user.Id)

		tx, err := w.DB()
		assert.NoError(err)
		where := "select * from db_test_user where name in ($1, $2)"
		rows, err := tx.Query(where, "alice", "bob")
		assert.NoError(err)
		defer func() { err := rows.Close(); assert.NoError(err) }()
		for rows.Next() {
			u, err := db_test.NewTestUser()
			assert.NoError(err)

			// scan the row into your Gorm struct
			err = w.ScanRows(rows, &u)
			assert.NoError(err)
			assert.Equal(user.PublicId, u.PublicId)
		}
	})
}

func testUser(t *testing.T, conn *gorm.DB, name, email, phoneNumber string) *db_test.TestUser {
	t.Helper()
	assert := assert.New(t)

	publicId, err := base62.Random(20)
	assert.NoError(err)
	u := &db_test.TestUser{
		StoreTestUser: &db_test.StoreTestUser{
			PublicId:    publicId,
			Name:        name,
			Email:       email,
			PhoneNumber: phoneNumber,
		},
	}
	if conn != nil {
		err = conn.Create(u).Error
		assert.NoError(err)
	}
	return u
}

func testId(t *testing.T) string {
	t.Helper()
	assert := assert.New(t)
	id, err := uuid.GenerateUUID()
	assert.NoError(err)
	return id
}
