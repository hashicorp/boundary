package db

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/golang/protobuf/ptypes"
	"github.com/hashicorp/boundary/internal/db/db_test"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/oplog/store"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/sdk/helper/base62"
	"github.com/jinzhu/gorm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestDb_UpdateUnsetField(t *testing.T) {
	db, _ := TestSetup(t, "postgres")
	rw := &Db{
		underlying: db,
	}
	tu := &db_test.TestUser{
		StoreTestUser: &db_test.StoreTestUser{
			PublicId: testId(t),
			Name:     "default",
		}}
	require.NoError(t, rw.Create(context.Background(), tu))

	updatedTu := tu.Clone().(*db_test.TestUser)
	updatedTu.Name = "updated"
	updatedTu.Email = "ignore"
	cnt, err := rw.Update(context.Background(), updatedTu, []string{"Name"}, nil)
	require.NoError(t, err)
	assert.Equal(t, 1, cnt)
	assert.Equal(t, "ignore", updatedTu.Email)
	assert.Equal(t, "updated", updatedTu.Name)
}

func TestDb_Update(t *testing.T) {
	db, _ := TestSetup(t, "postgres")
	now := &timestamp.Timestamp{Timestamp: ptypes.TimestampNow()}
	publicId, err := NewPublicId("testuser")
	require.NoError(t, err)
	id := testId(t)

	badVersion := uint32(22)
	versionOne := uint32(1)
	versionZero := uint32(0)

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
		wantVersion     int
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
			name: "simple-with-bad-version",
			args: args{
				i: &db_test.TestUser{
					StoreTestUser: &db_test.StoreTestUser{
						Name:        "simple-with-bad-version" + id,
						Email:       "updated" + id,
						PhoneNumber: "updated" + id,
					},
				},
				fieldMaskPaths: []string{"Name", "PhoneNumber"},
				setToNullPaths: []string{"Email"},
				opt:            []Option{WithVersion(&badVersion)},
			},
			want:       0,
			wantErr:    false,
			wantErrMsg: "",
		},
		{
			name: "simple-with-zero-version",
			args: args{
				i: &db_test.TestUser{
					StoreTestUser: &db_test.StoreTestUser{
						Name:        "simple-with-bad-version" + id,
						Email:       "updated" + id,
						PhoneNumber: "updated" + id,
					},
				},
				fieldMaskPaths: []string{"Name", "PhoneNumber"},
				setToNullPaths: []string{"Email"},
				opt:            []Option{WithVersion(&versionZero)},
			},
			want:       0,
			wantErr:    true,
			wantErrMsg: "update: with version option is zero: invalid parameter",
		},
		{
			name: "simple-with-version",
			args: args{
				i: &db_test.TestUser{
					StoreTestUser: &db_test.StoreTestUser{
						Name:        "simple-with-version" + id,
						Email:       "updated" + id,
						PhoneNumber: "updated" + id,
					},
				},
				fieldMaskPaths: []string{"Name", "PhoneNumber"},
				setToNullPaths: []string{"Email"},
				opt:            []Option{WithVersion(&versionOne)},
			},
			want:            1,
			wantErr:         false,
			wantErrMsg:      "",
			wantName:        "simple-with-version" + id,
			wantEmail:       "",
			wantPhoneNumber: "updated" + id,
			wantVersion:     2,
		},
		{
			name: "simple-with-where",
			args: args{
				i: &db_test.TestUser{
					StoreTestUser: &db_test.StoreTestUser{
						Name:        "simple-with-where" + id,
						Email:       "updated" + id,
						PhoneNumber: "updated" + id,
					},
				},
				fieldMaskPaths: []string{"Name", "PhoneNumber"},
				setToNullPaths: []string{"Email"},
				opt:            []Option{WithWhere("email = ? and phone_number = ?", id, id)},
			},
			want:            1,
			wantErr:         false,
			wantErrMsg:      "",
			wantName:        "simple-with-where" + id,
			wantEmail:       "",
			wantPhoneNumber: "updated" + id,
			wantVersion:     2,
		},
		{
			name: "simple-with-where-and-version",
			args: args{
				i: &db_test.TestUser{
					StoreTestUser: &db_test.StoreTestUser{
						Name:        "simple-with-where-and-version" + id,
						Email:       "updated" + id,
						PhoneNumber: "updated" + id,
					},
				},
				fieldMaskPaths: []string{"Name", "PhoneNumber"},
				setToNullPaths: []string{"Email"},
				opt:            []Option{WithWhere("email = ? and phone_number = ?", id, id), WithVersion(&versionOne)},
			},
			want:            1,
			wantErr:         false,
			wantErrMsg:      "",
			wantName:        "simple-with-where-and-version" + id,
			wantEmail:       "",
			wantPhoneNumber: "updated" + id,
			wantVersion:     2,
		},
		{
			name: "bad-with-where",
			args: args{
				i: &db_test.TestUser{
					StoreTestUser: &db_test.StoreTestUser{
						Name:        "bad-with-where" + id,
						Email:       "updated" + id,
						PhoneNumber: "updated" + id,
					},
				},
				fieldMaskPaths: []string{"Name", "PhoneNumber"},
				setToNullPaths: []string{"Email"},
				opt:            []Option{WithWhere("foo = ? and phone_number = ?", id, id)},
			},
			want:       0,
			wantErr:    true,
			wantErrMsg: `update: failed: pq: column "foo" does not exist`,
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
			name: "primary-key",
			args: args{
				i: &db_test.TestUser{
					StoreTestUser: &db_test.StoreTestUser{
						Name:        "primary-key" + id,
						Email:       "updated" + id,
						PhoneNumber: "updated" + id,
						PublicId:    publicId,
						CreateTime:  now,
						UpdateTime:  now,
					},
				},
				fieldMaskPaths: []string{"Id"},
				setToNullPaths: []string{"Email"},
			},
			want:       0,
			wantErr:    true,
			wantErrMsg: "update: not allowed on primary key field Id: invalid field mask",
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
			wantErrMsg: "update: interface is missing invalid parameter",
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
			assert, require := assert.New(t), require.New(t)
			rw := &Db{
				underlying: db,
			}
			u := testUser(t, db, tt.name+id, id, id)

			if tt.args.i != nil {
				tt.args.i.Id = u.Id
				tt.args.i.PublicId = u.PublicId
			}
			rowsUpdated, err := rw.Update(context.Background(), tt.args.i, tt.args.fieldMaskPaths, tt.args.setToNullPaths, tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
				assert.Equal(tt.want, rowsUpdated)
				assert.Equal(tt.wantErrMsg, err.Error())
				return
			}
			require.NoError(err)
			assert.Equal(tt.want, rowsUpdated)
			if tt.want == 0 {
				return
			}
			foundUser, err := db_test.NewTestUser()
			require.NoError(err)
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
			require.NoError(err)
			assert.Equal(tt.args.i.Id, foundUser.Id)
			assert.Equal(tt.wantName, foundUser.Name)
			assert.Equal(tt.wantEmail, foundUser.Email)
			assert.Equal(tt.wantPhoneNumber, foundUser.PhoneNumber)
			assert.NotEqual(now, foundUser.CreateTime)
			assert.NotEqual(now, foundUser.UpdateTime)
			assert.NotEqual(publicId, foundUser.PublicId)
			assert.Equal(u.Version+1, foundUser.Version)
		})
	}
	t.Run("no-version-field", func(t *testing.T) {
		assert := assert.New(t)
		w := Db{underlying: db}
		id, err := uuid.GenerateUUID()
		assert.NoError(err)
		car := testCar(t, db, "foo-"+id, id, int32(100))

		car.Name = "friendly-" + id
		versionOne := uint32(1)
		rowsUpdated, err := w.Update(context.Background(), car, []string{"Name"}, nil, WithVersion(&versionOne))
		assert.Error(err)
		assert.Equal(0, rowsUpdated)
	})
	t.Run("valid-WithOplog", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		w := Db{underlying: db}
		id, err := uuid.GenerateUUID()
		require.NoError(err)
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
		require.NoError(err)
		assert.Equal(1, rowsUpdated)

		foundUser, err := db_test.NewTestUser()
		require.NoError(err)
		foundUser.PublicId = user.PublicId
		err = w.LookupByPublicId(context.Background(), foundUser)
		require.NoError(err)
		assert.Equal(foundUser.Name, user.Name)

		err = TestVerifyOplog(t, &w, user.PublicId, WithOperation(oplog.OpType_OP_TYPE_UPDATE), WithCreateNotBefore(10*time.Second))
		require.NoError(err)
	})
	t.Run("both-WithOplog-NewOplogMsg", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		w := Db{underlying: db}
		id, err := uuid.GenerateUUID()
		require.NoError(err)
		user, err := db_test.NewTestUser()
		require.NoError(err)
		user.Name = "foo-" + id
		createMsg := oplog.Message{}
		err = w.Create(
			context.Background(),
			user,
			NewOplogMsg(&createMsg),
		)
		require.NoError(err)

		updateMsg := oplog.Message{}
		user.Name = "friendly-" + id
		rowsUpdated, err := w.Update(
			context.Background(),
			user,
			[]string{"Name"}, nil,
			NewOplogMsg(&updateMsg),
			WithOplog(TestWrapper(t), oplog.Metadata{"alice": []string{"bob"}}),
		)
		require.Error(err)
		assert.Equal(0, rowsUpdated)
		assert.True(errors.Is(err, ErrInvalidParameter))
	})
	t.Run("valid-NewOplogMsg", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		w := Db{underlying: db}

		ticket, err := w.GetTicket(&db_test.TestUser{})
		require.NoError(err)

		id, err := uuid.GenerateUUID()
		require.NoError(err)
		user, err := db_test.NewTestUser()
		require.NoError(err)
		user.Name = "foo-" + id
		createMsg := oplog.Message{}
		err = w.Create(
			context.Background(),
			user,
			NewOplogMsg(&createMsg),
		)
		require.NoError(err)

		updateMsg := oplog.Message{}
		user.Name = "friendly-" + id
		rowsUpdated, err := w.Update(context.Background(), user, []string{"Name"}, nil, NewOplogMsg(&updateMsg))
		require.NoError(err)
		assert.Equal(1, rowsUpdated)

		foundUser, err := db_test.NewTestUser()
		require.NoError(err)
		foundUser.PublicId = user.PublicId
		err = w.LookupByPublicId(context.Background(), foundUser)
		require.NoError(err)
		assert.Equal(foundUser.Name, user.Name)

		metadata := oplog.Metadata{
			"resource-public-id": []string{user.PublicId},
			// "op-type":            []string{oplog.OpType_OP_TYPE_UPDATE.String()},
		}
		err = w.WriteOplogEntryWith(context.Background(), TestWrapper(t), ticket, metadata, []*oplog.Message{&createMsg, &updateMsg})
		require.NoError(err)

		err = TestVerifyOplog(t, &w, user.PublicId, WithOperation(oplog.OpType_OP_TYPE_UNSPECIFIED), WithCreateNotBefore(10*time.Second))
		assert.NoError(err)
	})
	t.Run("vet-for-write", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
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
		require.NoError(err)

		user.Name = "friendly-" + id
		rowsUpdated, err := w.Update(context.Background(), user, []string{"Name"}, nil)
		require.NoError(err)
		assert.Equal(1, rowsUpdated)

		foundUser := &testUserWithVet{PublicId: user.PublicId}
		require.NoError(err)
		foundUser.PublicId = user.PublicId
		err = w.LookupByPublicId(context.Background(), foundUser)
		require.NoError(err)
		assert.Equal(foundUser.Name, user.Name)

		user.PublicId = "not-allowed-by-vet-for-write"
		rowsUpdated, err = w.Update(context.Background(), user, []string{"PublicId"}, nil)
		require.Error(err)
		assert.Equal(0, rowsUpdated)
	})
	t.Run("nil-tx", func(t *testing.T) {
		assert := assert.New(t)
		w := Db{underlying: nil}
		id, err := uuid.GenerateUUID()
		assert.NoError(err)

		user := testUser(t, db, "foo-"+id, id, id)
		rowsUpdated, err := w.Update(context.Background(), user, []string{"Name"}, nil)
		assert.Error(err)
		assert.Equal(0, rowsUpdated)
		assert.Equal("update: missing underlying db invalid parameter", err.Error())
	})
	t.Run("no-wrapper-WithOplog", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		w := Db{underlying: db}
		id, err := uuid.GenerateUUID()
		require.NoError(err)
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
		require.Error(err)
		assert.Equal(0, rowsUpdated)
		assert.Equal("update: oplog validation failed: error no wrapper WithOplog: invalid parameter", err.Error())
	})
	t.Run("no-metadata-WithOplog", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		w := Db{underlying: db}
		id, err := uuid.GenerateUUID()
		require.NoError(err)
		user := testUser(t, db, "foo-"+id, id, id)
		user.Name = "friendly-" + id
		rowsUpdated, err := w.Update(context.Background(), user, []string{"Name"}, nil,
			WithOplog(
				TestWrapper(t),
				nil,
			),
		)
		require.Error(err)
		assert.Equal(0, rowsUpdated)
		assert.Equal("update: oplog validation failed: error no metadata for WithOplog: invalid parameter", err.Error())
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
	db, _ := TestSetup(t, "postgres")
	t.Run("simple", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		w := Db{underlying: db}
		id, err := uuid.GenerateUUID()
		require.NoError(err)
		user, err := db_test.NewTestUser()
		require.NoError(err)
		ts := &timestamp.Timestamp{Timestamp: ptypes.TimestampNow()}
		user.CreateTime = ts
		user.UpdateTime = ts
		user.Name = "foo-" + id
		err = w.Create(context.Background(), user)
		require.NoError(err)
		assert.NotEmpty(user.Id)
		// make sure the database controlled the timestamp values
		assert.NotEqual(ts, user.GetCreateTime())
		assert.NotEqual(ts, user.GetUpdateTime())

		foundUser, err := db_test.NewTestUser()
		require.NoError(err)
		foundUser.PublicId = user.PublicId
		err = w.LookupByPublicId(context.Background(), foundUser)
		require.NoError(err)
		assert.Equal(foundUser.Id, user.Id)
	})
	t.Run("valid-WithOplog", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		w := Db{underlying: db}
		id, err := uuid.GenerateUUID()
		require.NoError(err)
		user, err := db_test.NewTestUser()
		require.NoError(err)
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
		require.NoError(err)
		require.NotEmpty(user.Id)

		foundUser, err := db_test.NewTestUser()
		require.NoError(err)
		foundUser.PublicId = user.PublicId
		err = w.LookupByPublicId(context.Background(), foundUser)
		require.NoError(err)
		assert.Equal(foundUser.Id, user.Id)
	})
	t.Run("both-Oplog-NewOplogMsg", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		w := Db{underlying: db}
		id, err := uuid.GenerateUUID()
		require.NoError(err)
		user, err := db_test.NewTestUser()
		require.NoError(err)
		user.Name = "foo-" + id
		createMsg := oplog.Message{}
		err = w.Create(
			context.Background(),
			user,
			NewOplogMsg(&createMsg),
			WithOplog(TestWrapper(t), oplog.Metadata{"alice": []string{"bob"}}),
		)
		require.Error(err)
		assert.True(errors.Is(err, ErrInvalidParameter))
	})
	t.Run("valid-NewOplogMsg", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		w := Db{underlying: db}

		ticket, err := w.GetTicket(&db_test.TestUser{})
		require.NoError(err)

		id, err := uuid.GenerateUUID()
		require.NoError(err)
		user, err := db_test.NewTestUser()
		require.NoError(err)
		user.Name = "foo-" + id
		createMsg := oplog.Message{}
		err = w.Create(
			context.Background(),
			user,
			NewOplogMsg(&createMsg),
		)
		require.NoError(err)

		updateMsg := oplog.Message{}
		user.Name = "friendly-" + id
		rowsUpdated, err := w.Update(context.Background(), user, []string{"Name"}, nil, NewOplogMsg(&updateMsg))
		require.NoError(err)
		assert.Equal(1, rowsUpdated)

		foundUser, err := db_test.NewTestUser()
		require.NoError(err)
		foundUser.PublicId = user.PublicId
		err = w.LookupByPublicId(context.Background(), foundUser)
		require.NoError(err)
		assert.Equal(foundUser.Name, user.Name)

		metadata := oplog.Metadata{
			"resource-public-id": []string{user.PublicId},
			// "op-type":            []string{oplog.OpType_OP_TYPE_UPDATE.String()},
		}
		err = w.WriteOplogEntryWith(context.Background(), TestWrapper(t), ticket, metadata, []*oplog.Message{&createMsg, &updateMsg})
		require.NoError(err)

		err = TestVerifyOplog(t, &w, user.PublicId, WithOperation(oplog.OpType_OP_TYPE_UNSPECIFIED), WithCreateNotBefore(10*time.Second))
		require.NoError(err)
	})
	t.Run("no-wrapper-WithOplog", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		w := Db{underlying: db}
		id, err := uuid.GenerateUUID()
		require.NoError(err)
		user, err := db_test.NewTestUser()
		require.NoError(err)
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
		require.Error(err)
		assert.Equal("create: oplog validation failed: error no wrapper WithOplog: invalid parameter", err.Error())
	})
	t.Run("no-metadata-WithOplog", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		w := Db{underlying: db}
		id, err := uuid.GenerateUUID()
		require.NoError(err)
		user, err := db_test.NewTestUser()
		require.NoError(err)
		user.Name = "foo-" + id
		err = w.Create(
			context.Background(),
			user,
			WithOplog(
				TestWrapper(t),
				nil,
			),
		)
		require.Error(err)
		assert.Equal("create: oplog validation failed: error no metadata for WithOplog: invalid parameter", err.Error())
	})
	t.Run("nil-tx", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		w := Db{underlying: nil}
		id, err := uuid.GenerateUUID()
		require.NoError(err)
		user, err := db_test.NewTestUser()
		require.NoError(err)
		user.Name = "foo-" + id
		err = w.Create(context.Background(), user)
		require.Error(err)
		assert.Equal("create: missing underlying db: invalid parameter", err.Error())
	})
}

func TestDb_LookupByName(t *testing.T) {
	t.Parallel()
	db, _ := TestSetup(t, "postgres")
	t.Run("simple", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		w := Db{underlying: db}
		id, err := uuid.GenerateUUID()
		require.NoError(err)
		user, err := db_test.NewTestUser()
		require.NoError(err)
		user.Name = "fn-" + id
		err = w.Create(context.Background(), user)
		require.NoError(err)
		assert.NotEmpty(user.Id)

		foundUser, err := db_test.NewTestUser()
		require.NoError(err)
		foundUser.Name = "fn-" + id
		err = w.LookupByName(context.Background(), foundUser)
		require.NoError(err)
		assert.Equal(foundUser.Id, user.Id)
	})
	t.Run("tx-nil,", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		w := Db{}
		foundUser, err := db_test.NewTestUser()
		require.NoError(err)
		foundUser.Name = "fn-name"
		err = w.LookupByName(context.Background(), foundUser)
		require.Error(err)
		assert.Equal("error underlying db nil for lookup by name", err.Error())
	})
	t.Run("no-friendly-name-set", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		w := Db{underlying: db}
		foundUser, err := db_test.NewTestUser()
		require.NoError(err)
		err = w.LookupByName(context.Background(), foundUser)
		require.Error(err)
		assert.Equal("error name empty string for lookup by name", err.Error())
	})
	t.Run("not-found", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		w := Db{underlying: db}
		id, err := uuid.GenerateUUID()
		require.NoError(err)

		foundUser, err := db_test.NewTestUser()
		require.NoError(err)
		foundUser.Name = "fn-" + id
		err = w.LookupByName(context.Background(), foundUser)
		require.Error(err)
		assert.Equal(ErrRecordNotFound, err)
	})
}

func TestDb_LookupByPublicId(t *testing.T) {
	t.Parallel()
	db, _ := TestSetup(t, "postgres")
	t.Run("simple", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		w := Db{underlying: db}
		id, err := uuid.GenerateUUID()
		require.NoError(err)
		user, err := db_test.NewTestUser()
		require.NoError(err)
		user.Name = "foo-" + id
		err = w.Create(context.Background(), user)
		require.NoError(err)
		assert.NotEmpty(user.PublicId)

		foundUser, err := db_test.NewTestUser()
		require.NoError(err)
		foundUser.PublicId = user.PublicId
		err = w.LookupByPublicId(context.Background(), foundUser)
		require.NoError(err)
		assert.Equal(foundUser.Id, user.Id)
	})
	t.Run("tx-nil,", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		w := Db{}
		foundUser, err := db_test.NewTestUser()
		require.NoError(err)
		err = w.LookupByPublicId(context.Background(), foundUser)
		require.Error(err)
		assert.Equal("lookup by id: underlying db nil invalid parameter", err.Error())
	})
	t.Run("no-public-id-set", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		w := Db{underlying: db}
		foundUser, err := db_test.NewTestUser()
		foundUser.PublicId = ""
		require.NoError(err)
		err = w.LookupByPublicId(context.Background(), foundUser)
		require.Error(err)
		assert.Equal("lookup by id: primary key unset invalid parameter", err.Error())
	})
	t.Run("not-found", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		w := Db{underlying: db}
		id, err := uuid.GenerateUUID()
		require.NoError(err)
		foundUser, err := db_test.NewTestUser()
		require.NoError(err)
		foundUser.PublicId = id
		err = w.LookupByPublicId(context.Background(), foundUser)
		require.Error(err)
		assert.Equal(ErrRecordNotFound, err)
	})
}

func TestDb_LookupWhere(t *testing.T) {
	t.Parallel()
	db, _ := TestSetup(t, "postgres")
	t.Run("simple", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		w := Db{underlying: db}
		id, err := uuid.GenerateUUID()
		require.NoError(err)
		user, err := db_test.NewTestUser()
		require.NoError(err)
		user.Name = "foo-" + id
		err = w.Create(context.Background(), user)
		require.NoError(err)
		assert.NotEmpty(user.PublicId)

		var foundUser db_test.TestUser
		err = w.LookupWhere(context.Background(), &foundUser, "public_id = ?", user.PublicId)
		require.NoError(err)
		assert.Equal(foundUser.Id, user.Id)
	})
	t.Run("tx-nil,", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		w := Db{}
		var foundUser db_test.TestUser
		err := w.LookupWhere(context.Background(), &foundUser, "public_id = ?", 1)
		require.Error(err)
		assert.Equal("error underlying db nil for lookup by", err.Error())
	})
	t.Run("not-found", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		w := Db{underlying: db}
		id, err := uuid.GenerateUUID()
		require.NoError(err)

		var foundUser db_test.TestUser
		err = w.LookupWhere(context.Background(), &foundUser, "public_id = ?", id)
		require.Error(err)
		assert.Equal(ErrRecordNotFound, err)
		assert.True(errors.Is(err, ErrRecordNotFound))
	})
	t.Run("bad-where", func(t *testing.T) {
		require := require.New(t)
		w := Db{underlying: db}
		id, err := uuid.GenerateUUID()
		require.NoError(err)

		var foundUser db_test.TestUser
		err = w.LookupWhere(context.Background(), &foundUser, "? = ?", id)
		require.Error(err)
	})
}

func TestDb_SearchWhere(t *testing.T) {
	t.Parallel()
	db, _ := TestSetup(t, "postgres")
	knownUser := testUser(t, db, "zedUser", "", "")

	type args struct {
		where string
		arg   []interface{}
		opt   []Option
	}
	tests := []struct {
		name          string
		db            Db
		createCnt     int
		args          args
		wantCnt       int
		wantErr       bool
		wantNameOrder bool
	}{
		{
			name:      "no-limit",
			db:        Db{underlying: db},
			createCnt: 10,
			args: args{
				where: "1=1",
				opt:   []Option{WithLimit(-1), WithOrder("name asc")},
			},
			wantCnt:       11, // there's an additional knownUser
			wantErr:       false,
			wantNameOrder: true,
		},
		{
			name:      "custom-limit",
			db:        Db{underlying: db},
			createCnt: 10,
			args: args{
				where: "1=1",
				opt:   []Option{WithLimit(3)},
			},
			wantCnt: 3,
			wantErr: false,
		},
		{
			name:      "simple",
			db:        Db{underlying: db},
			createCnt: 1,
			args: args{
				where: "public_id = ?",
				arg:   []interface{}{knownUser.PublicId},
				opt:   []Option{WithLimit(3)},
			},
			wantCnt: 1,
			wantErr: false,
		},
		{
			name:      "not-found",
			db:        Db{underlying: db},
			createCnt: 1,
			args: args{
				where: "public_id = ?",
				arg:   []interface{}{"bad-id"},
				opt:   []Option{WithLimit(3)},
			},
			wantCnt: 0,
			wantErr: false,
		},
		{
			name:      "bad-where",
			db:        Db{underlying: db},
			createCnt: 1,
			args: args{
				where: "bad_column_name = ?",
				arg:   []interface{}{knownUser.PublicId},
				opt:   []Option{WithLimit(3)},
			},
			wantCnt: 0,
			wantErr: true,
		},
		{
			name:      "nil-underlying",
			db:        Db{},
			createCnt: 1,
			args: args{
				where: "public_id = ?",
				arg:   []interface{}{knownUser.PublicId},
				opt:   []Option{WithLimit(3)},
			},
			wantCnt: 0,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			testUsers := []*db_test.TestUser{}
			for i := 0; i < tt.createCnt; i++ {
				testUsers = append(testUsers, testUser(t, db, tt.name+strconv.Itoa(i), "", ""))
			}
			assert.Equal(tt.createCnt, len(testUsers))

			var foundUsers []db_test.TestUser
			db.LogMode(true)
			defer db.LogMode(false)
			err := tt.db.SearchWhere(context.Background(), &foundUsers, tt.args.where, tt.args.arg, tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
				return
			}
			require.NoError(err)
			assert.Equal(tt.wantCnt, len(foundUsers))
			if tt.wantNameOrder {
				assert.Equal(tt.name+strconv.Itoa(0), foundUsers[0].Name)
				for i, u := range foundUsers {
					if u.Name != "zedUser" {
						assert.Equal(tt.name+strconv.Itoa(i), u.Name)
					}
				}
			}
		})
	}
}

func TestDb_Exec(t *testing.T) {
	t.Parallel()
	t.Run("update", func(t *testing.T) {
		db, _ := TestSetup(t, "postgres")
		require := require.New(t)
		w := Db{underlying: db}
		id := testId(t)
		user, err := db_test.NewTestUser()
		require.NoError(err)
		user.Name = "foo-" + id
		err = w.Create(context.Background(), user)
		require.NoError(err)
		require.NotEmpty(user.Id)
		rowsAffected, err := w.Exec(context.Background(), "update db_test_user set name = ? where public_id = ?", []interface{}{"updated-" + id, user.PublicId})
		require.NoError(err)
		require.Equal(1, rowsAffected)
	})
}
func TestDb_DoTx(t *testing.T) {
	t.Parallel()
	db, _ := TestSetup(t, "postgres")
	t.Run("valid-with-10-retries", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		w := &Db{underlying: db}
		attempts := 0
		got, err := w.DoTx(context.Background(), 10, ExpBackoff{},
			func(Reader, Writer) error {
				attempts += 1
				if attempts < 9 {
					return oplog.ErrTicketAlreadyRedeemed
				}
				return nil
			})
		require.NoError(err)
		assert.Equal(8, got.Retries)
		assert.Equal(9, attempts) // attempted 1 + 8 retries
	})
	t.Run("valid-with-1-retries", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		w := &Db{underlying: db}
		attempts := 0
		got, err := w.DoTx(context.Background(), 1, ExpBackoff{},
			func(Reader, Writer) error {
				attempts += 1
				if attempts < 2 {
					return oplog.ErrTicketAlreadyRedeemed
				}
				return nil
			})
		require.NoError(err)
		assert.Equal(1, got.Retries)
		assert.Equal(2, attempts) // attempted 1 + 8 retries
	})
	t.Run("valid-with-2-retries", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		w := &Db{underlying: db}
		attempts := 0
		got, err := w.DoTx(context.Background(), 3, ExpBackoff{},
			func(Reader, Writer) error {
				attempts += 1
				if attempts < 3 {
					return oplog.ErrTicketAlreadyRedeemed
				}
				return nil
			})
		require.NoError(err)
		assert.Equal(2, got.Retries)
		assert.Equal(3, attempts) // attempted 1 + 8 retries
	})
	t.Run("valid-with-4-retries", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		w := &Db{underlying: db}
		attempts := 0
		got, err := w.DoTx(context.Background(), 4, ExpBackoff{},
			func(Reader, Writer) error {
				attempts += 1
				if attempts < 4 {
					return oplog.ErrTicketAlreadyRedeemed
				}
				return nil
			})
		require.NoError(err)
		assert.Equal(3, got.Retries)
		assert.Equal(4, attempts) // attempted 1 + 8 retries
	})
	t.Run("zero-retries", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		w := &Db{underlying: db}
		attempts := 0
		got, err := w.DoTx(context.Background(), 0, ExpBackoff{}, func(Reader, Writer) error { attempts += 1; return nil })
		require.NoError(err)
		assert.Equal(RetryInfo{}, got)
		assert.Equal(1, attempts)
	})
	t.Run("nil-tx", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		w := &Db{nil}
		attempts := 0
		got, err := w.DoTx(context.Background(), 1, ExpBackoff{}, func(Reader, Writer) error { attempts += 1; return nil })
		require.Error(err)
		assert.Equal(RetryInfo{}, got)
		assert.Equal("do underlying db is nil", err.Error())
	})
	t.Run("not-a-retry-err", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		w := &Db{underlying: db}
		got, err := w.DoTx(context.Background(), 1, ExpBackoff{}, func(Reader, Writer) error { return errors.New("not a retry error") })
		require.Error(err)
		assert.Equal(RetryInfo{}, got)
		assert.NotEqual(err, oplog.ErrTicketAlreadyRedeemed)
	})
	t.Run("too-many-retries", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		w := &Db{underlying: db}
		attempts := 0
		got, err := w.DoTx(context.Background(), 2, ExpBackoff{}, func(Reader, Writer) error { attempts += 1; return oplog.ErrTicketAlreadyRedeemed })
		require.Error(err)
		assert.Equal(3, got.Retries)
		assert.Equal("Too many retries: 3 of 3", err.Error())
	})
	t.Run("updating-good-bad-good", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		rw := Db{underlying: db}
		id, err := uuid.GenerateUUID()
		require.NoError(err)
		user, err := db_test.NewTestUser()
		require.NoError(err)
		user.Name = "foo-" + id
		err = rw.Create(context.Background(), user)
		require.NoError(err)
		require.NotZero(user.Id)

		_, err = rw.DoTx(context.Background(), 10, ExpBackoff{}, func(r Reader, w Writer) error {
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
		require.NoError(err)

		foundUser, err := db_test.NewTestUser()
		assert.NoError(err)
		foundUser.PublicId = user.PublicId
		err = rw.LookupByPublicId(context.Background(), foundUser)
		require.NoError(err)
		assert.Equal(foundUser.Name, user.Name)

		user2, err := db_test.NewTestUser()
		require.NoError(err)
		_, err = rw.DoTx(context.Background(), 10, ExpBackoff{}, func(_ Reader, w Writer) error {
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
		require.Error(err)
		err = rw.LookupByPublicId(context.Background(), foundUser)
		require.NoError(err)
		assert.NotEqual(foundUser.Name, user2.Name)

		_, err = rw.DoTx(context.Background(), 10, ExpBackoff{}, func(r Reader, w Writer) error {
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
		require.NoError(err)
		err = rw.LookupByPublicId(context.Background(), foundUser)
		require.NoError(err)
		assert.Equal(foundUser.Name, user.Name)
	})
}

func TestDb_Delete(t *testing.T) {
	db, _ := TestSetup(t, "postgres")
	newUser := func() *db_test.TestUser {
		w := &Db{
			underlying: db,
		}
		u, err := db_test.NewTestUser()
		require.NoError(t, err)
		err = w.Create(context.Background(), u)
		require.NoError(t, err)
		return u
	}
	notFoundUser := func() *db_test.TestUser {
		u, err := db_test.NewTestUser()
		require.NoError(t, err)
		u.Id = 1111111
		return u
	}

	newMetadata := func(publicId string) oplog.Metadata {
		return oplog.Metadata{
			"op-type":            []string{oplog.OpType_OP_TYPE_DELETE.String()},
			"resource-public-id": []string{publicId},
		}
	}
	type args struct {
		i        *db_test.TestUser
		opt      []Option
		metadata func(publicId string) oplog.Metadata
	}
	tests := []struct {
		name       string
		underlying *gorm.DB
		wrapper    wrapping.Wrapper
		args       args
		want       int
		wantOplog  bool
		wantErr    bool
		wantErrIs  error
	}{
		{
			name:       "simple-no-oplog",
			underlying: db,
			wrapper:    TestWrapper(t),
			args: args{
				i: newUser(),
			},
			want:    1,
			wantErr: false,
		},
		{
			name:       "valid-with-oplog",
			underlying: db,
			wrapper:    TestWrapper(t),
			args: args{
				i:        newUser(),
				metadata: newMetadata,
			},
			wantOplog: true,
			want:      1,
			wantErr:   false,
		},
		{
			name:       "nil-wrapper",
			underlying: db,
			wrapper:    nil,
			args: args{
				i:        newUser(),
				metadata: newMetadata,
			},
			wantOplog: true,
			want:      0,
			wantErr:   true,
			wantErrIs: ErrInvalidParameter,
		},
		{
			name:       "nil-metadata",
			underlying: db,
			wrapper:    nil,
			args: args{
				i:        newUser(),
				metadata: func(string) oplog.Metadata { return nil },
			},
			wantOplog: true,
			want:      0,
			wantErr:   true,
			wantErrIs: ErrInvalidParameter,
		},
		{
			name:       "nil-underlying",
			underlying: nil,
			wrapper:    TestWrapper(t),
			args: args{
				i: newUser(),
			},
			want:      0,
			wantErr:   true,
			wantErrIs: ErrInvalidParameter,
		},
		{
			name:       "not-found",
			underlying: db,
			wrapper:    TestWrapper(t),
			args: args{
				i: notFoundUser(),
			},
			want:    0,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require := require.New(t)
			assert := assert.New(t)
			rw := &Db{
				underlying: tt.underlying,
			}
			if tt.wantOplog {
				metadata := tt.args.metadata(tt.args.i.PublicId)
				opLog := WithOplog(tt.wrapper, metadata)
				tt.args.opt = append(tt.args.opt, opLog)
			}
			got, err := rw.Delete(context.Background(), tt.args.i, tt.args.opt...)
			assert.Equal(tt.want, got)
			if tt.wantErr {
				require.Error(err)
				if tt.wantErrIs != nil {
					assert.Truef(errors.Is(err, tt.wantErrIs), "received unexpected error: %v", err)
				}
				err := TestVerifyOplog(t, rw, tt.args.i.GetPublicId(), WithOperation(oplog.OpType_OP_TYPE_DELETE), WithCreateNotBefore(5*time.Second))
				assert.Error(err)
				return
			}
			require.NoError(err)
			assert.Equal(tt.want, got)

			foundUser := tt.args.i.Clone().(*db_test.TestUser)
			foundUser.PublicId = tt.args.i.PublicId
			err = rw.LookupByPublicId(context.Background(), foundUser)
			assert.Error(err)
			assert.Equal(ErrRecordNotFound, err)

			err = TestVerifyOplog(t, rw, tt.args.i.GetPublicId(), WithOperation(oplog.OpType_OP_TYPE_DELETE), WithCreateNotBefore(5*time.Second))
			switch {
			case tt.wantOplog:
				assert.NoError(err)
			default:
				assert.Error(err)
			}
		})
		t.Run("both-WithOplog-NewOplogMsg", func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			w := Db{underlying: db}
			id, err := uuid.GenerateUUID()
			require.NoError(err)
			user, err := db_test.NewTestUser()
			require.NoError(err)
			user.Name = "foo-" + id
			createMsg := oplog.Message{}
			err = w.Create(
				context.Background(),
				user,
				NewOplogMsg(&createMsg),
			)
			require.NoError(err)

			deleteMsg := oplog.Message{}
			rowsDeleted, err := w.Delete(context.Background(), user, NewOplogMsg(&deleteMsg), WithOplog(TestWrapper(t), oplog.Metadata{"alice": []string{"bob"}}))
			require.Error(err)
			assert.Equal(0, rowsDeleted)
			assert.True(errors.Is(err, ErrInvalidParameter))
		})
		t.Run("valid-NewOplogMsg", func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			w := Db{underlying: db}

			ticket, err := w.GetTicket(&db_test.TestUser{})
			require.NoError(err)

			id, err := uuid.GenerateUUID()
			require.NoError(err)
			user, err := db_test.NewTestUser()
			require.NoError(err)
			user.Name = "foo-" + id
			createMsg := oplog.Message{}
			err = w.Create(
				context.Background(),
				user,
				NewOplogMsg(&createMsg),
			)
			require.NoError(err)

			deleteMsg := oplog.Message{}
			rowsDeleted, err := w.Delete(context.Background(), user, NewOplogMsg(&deleteMsg))
			require.NoError(err)
			assert.Equal(1, rowsDeleted)

			foundUser, err := db_test.NewTestUser()
			require.NoError(err)
			foundUser.PublicId = user.PublicId
			err = w.LookupByPublicId(context.Background(), foundUser)
			require.Error(err)
			assert.True(errors.Is(err, ErrRecordNotFound))

			metadata := oplog.Metadata{
				"resource-public-id": []string{user.PublicId},
			}
			err = w.WriteOplogEntryWith(context.Background(), TestWrapper(t), ticket, metadata, []*oplog.Message{&createMsg, &deleteMsg})
			require.NoError(err)

			err = TestVerifyOplog(t, &w, user.PublicId, WithOperation(oplog.OpType_OP_TYPE_UNSPECIFIED), WithCreateNotBefore(10*time.Second))
			require.NoError(err)
		})
	}
}

func TestDb_ScanRows(t *testing.T) {
	t.Parallel()
	db, _ := TestSetup(t, "postgres")
	t.Run("valid", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		w := Db{underlying: db}
		user, err := db_test.NewTestUser()
		require.NoError(err)
		err = w.Create(context.Background(), user)
		require.NoError(err)
		assert.NotEmpty(user.Id)
		where := "select * from db_test_user where name in ($1, $2)"
		rows, err := w.Query(context.Background(), where, []interface{}{"alice", "bob"})
		require.NoError(err)
		defer func() { err := rows.Close(); assert.NoError(err) }()
		for rows.Next() {
			u, err := db_test.NewTestUser()
			require.NoError(err)

			// scan the row into your Gorm struct
			err = w.ScanRows(rows, &u)
			require.NoError(err)
			assert.Equal(user.PublicId, u.PublicId)
		}
	})
}

func TestDb_Query(t *testing.T) {
	t.Parallel()
	db, _ := TestSetup(t, "postgres")
	t.Run("valid", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		rw := Db{underlying: db}
		user, err := db_test.NewTestUser()
		user.Name = "alice"
		require.NoError(err)
		err = rw.Create(context.Background(), user)
		require.NoError(err)
		assert.NotEmpty(user.Id)
		assert.Equal("alice", user.Name)

		where := "select * from db_test_user where name in ($1, $2)"
		rows, err := rw.Query(context.Background(), where, []interface{}{"alice", "bob"})
		require.NoError(err)
		defer func() { err := rows.Close(); assert.NoError(err) }()
		for rows.Next() {
			u, err := db_test.NewTestUser()
			require.NoError(err)
			// scan the row into your Gorm struct
			err = rw.ScanRows(rows, &u)
			require.NoError(err)
			assert.Equal(user.PublicId, u.PublicId)
		}
	})
}

func TestDb_CreateItems(t *testing.T) {
	db, _ := TestSetup(t, "postgres")
	testOplogResourceId := testId(t)

	createFn := func() []interface{} {
		results := []interface{}{}
		for i := 0; i < 10; i++ {
			u, err := db_test.NewTestUser()
			require.NoError(t, err)
			results = append(results, u)
		}
		return results
	}
	createMixedFn := func() []interface{} {
		u, err := db_test.NewTestUser()
		require.NoError(t, err)
		c, err := db_test.NewTestCar()
		require.NoError(t, err)
		return []interface{}{
			u,
			c,
		}
	}

	returnedMsgs := []*oplog.Message{}

	type args struct {
		createItems []interface{}
		opt         []Option
	}
	tests := []struct {
		name          string
		underlying    *gorm.DB
		args          args
		wantOplogId   string
		wantOplogMsgs bool
		wantErr       bool
		wantErrIs     error
	}{
		{
			name:       "simple",
			underlying: db,
			args: args{
				createItems: createFn(),
			},
			wantErr: false,
		},
		{
			name:       "withOplog",
			underlying: db,
			args: args{
				createItems: createFn(),
				opt: []Option{
					WithOplog(
						TestWrapper(t),
						oplog.Metadata{
							"resource-public-id": []string{testOplogResourceId},
							"op-type":            []string{oplog.OpType_OP_TYPE_CREATE.String()},
						},
					),
				},
			},
			wantOplogId: testOplogResourceId,
			wantErr:     false,
		},
		{
			name:       "NewOplogMsgs",
			underlying: db,
			args: args{
				createItems: createFn(),
				opt: []Option{
					NewOplogMsgs(&returnedMsgs),
				},
			},
			wantOplogMsgs: true,
			wantErr:       false,
		},
		{
			name:       "withOplog and NewOplogMsgs",
			underlying: db,
			args: args{
				createItems: createFn(),
				opt: []Option{
					NewOplogMsgs(&[]*oplog.Message{}),
					WithOplog(
						TestWrapper(t),
						oplog.Metadata{
							"resource-public-id": []string{testOplogResourceId},
							"op-type":            []string{oplog.OpType_OP_TYPE_CREATE.String()},
						},
					),
				},
			},
			wantErrIs: ErrInvalidParameter,
			wantErr:   true,
		},
		{
			name:       "mixed items",
			underlying: db,
			args: args{
				createItems: createMixedFn(),
			},
			wantErr:   true,
			wantErrIs: ErrInvalidParameter,
		},
		{
			name:       "bad oplog opt: nil metadata",
			underlying: nil,
			args: args{
				createItems: createFn(),
				opt: []Option{
					WithOplog(
						TestWrapper(t),
						nil,
					),
				},
			},
			wantErr:   true,
			wantErrIs: ErrInvalidParameter,
		},
		{
			name:       "bad oplog opt: nil wrapper",
			underlying: nil,
			args: args{
				createItems: createFn(),
				opt: []Option{
					WithOplog(
						nil,
						oplog.Metadata{
							"resource-public-id": []string{"doesn't matter since wrapper is nil"},
							"op-type":            []string{oplog.OpType_OP_TYPE_CREATE.String()},
						},
					),
				},
			},
			wantErr:   true,
			wantErrIs: ErrInvalidParameter,
		},
		{
			name:       "bad opt: WithLookup",
			underlying: nil,
			args: args{
				createItems: createFn(),
				opt:         []Option{WithLookup(true)},
			},
			wantErr:   true,
			wantErrIs: ErrInvalidParameter,
		},
		{
			name:       "nil underlying",
			underlying: nil,
			args: args{
				createItems: createFn(),
			},
			wantErr:   true,
			wantErrIs: ErrInvalidParameter,
		},
		{
			name:       "empty items",
			underlying: db,
			args: args{
				createItems: []interface{}{},
			},
			wantErr:   true,
			wantErrIs: ErrInvalidParameter,
		},
		{
			name:       "nil items",
			underlying: db,
			args: args{
				createItems: nil,
			},
			wantErr:   true,
			wantErrIs: ErrInvalidParameter,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			rw := &Db{
				underlying: tt.underlying,
			}
			err := rw.CreateItems(context.Background(), tt.args.createItems, tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
				if tt.wantErrIs != nil {
					assert.Truef(errors.Is(err, tt.wantErrIs), "unexpected error: %s", err.Error())
				}
				return
			}
			require.NoError(err)
			for _, item := range tt.args.createItems {
				u := db_test.AllocTestUser()
				u.PublicId = item.(*db_test.TestUser).PublicId
				err := rw.LookupByPublicId(context.Background(), &u)
				assert.NoError(err)
				if _, ok := item.(*db_test.TestUser); ok {
					assert.Truef(proto.Equal(item.(*db_test.TestUser).StoreTestUser, u.StoreTestUser), "%s and %s should be equal", item, u)
				}
			}
			if tt.wantOplogId != "" {
				err = TestVerifyOplog(t, rw, tt.wantOplogId, WithOperation(oplog.OpType_OP_TYPE_CREATE), WithCreateNotBefore(10*time.Second))
				assert.NoError(err)
			}
			if tt.wantOplogMsgs {
				assert.Equal(len(tt.args.createItems), len(returnedMsgs))
				for _, m := range returnedMsgs {
					assert.Equal(m.OpType, oplog.OpType_OP_TYPE_CREATE)
				}
			}
		})
	}
}

func TestDb_DeleteItems(t *testing.T) {
	db, _ := TestSetup(t, "postgres")
	testOplogResourceId := testId(t)

	createFn := func() []interface{} {
		results := []interface{}{}
		for i := 0; i < 10; i++ {
			u := testUser(t, db, "", "", "")
			results = append(results, u)
		}
		return results
	}

	returnedMsgs := []*oplog.Message{}

	type args struct {
		deleteItems []interface{}
		opt         []Option
	}
	tests := []struct {
		name            string
		underlying      *gorm.DB
		args            args
		wantRowsDeleted int
		wantOplogId     string
		wantOplogMsgs   bool
		wantErr         bool
		wantErrIs       error
	}{
		{
			name:       "simple",
			underlying: db,
			args: args{
				deleteItems: createFn(),
			},
			wantRowsDeleted: 10,
			wantErr:         false,
		},
		{
			name:       "NewOplogMsgs",
			underlying: db,
			args: args{
				deleteItems: createFn(),
				opt: []Option{
					NewOplogMsgs(&returnedMsgs),
				},
			},
			wantRowsDeleted: 10,
			wantErr:         false,
		},
		{
			name:       "withOplog and NewOplogMsgs",
			underlying: db,
			args: args{
				deleteItems: createFn(),
				opt: []Option{
					NewOplogMsgs(&[]*oplog.Message{}),
					WithOplog(
						TestWrapper(t),
						oplog.Metadata{
							"resource-public-id": []string{testOplogResourceId},
							"op-type":            []string{oplog.OpType_OP_TYPE_DELETE.String()},
						},
					),
				},
			},
			wantErr:   true,
			wantErrIs: ErrInvalidParameter,
		},
		{
			name:       "withOplog",
			underlying: db,
			args: args{
				deleteItems: createFn(),
				opt: []Option{
					WithOplog(
						TestWrapper(t),
						oplog.Metadata{
							"resource-public-id": []string{testOplogResourceId},
							"op-type":            []string{oplog.OpType_OP_TYPE_DELETE.String()},
						},
					),
				},
			},
			wantRowsDeleted: 10,
			wantOplogId:     testOplogResourceId,
			wantErr:         false,
		},
		{
			name:       "bad oplog opt: nil metadata",
			underlying: nil,
			args: args{
				deleteItems: createFn(),
				opt: []Option{
					WithOplog(
						TestWrapper(t),
						nil,
					),
				},
			},
			wantErr:   true,
			wantErrIs: ErrInvalidParameter,
		},
		{
			name:       "bad oplog opt: nil wrapper",
			underlying: nil,
			args: args{
				deleteItems: createFn(),
				opt: []Option{
					WithOplog(
						nil,
						oplog.Metadata{
							"resource-public-id": []string{"doesn't matter since wrapper is nil"},
							"op-type":            []string{oplog.OpType_OP_TYPE_CREATE.String()},
						},
					),
				},
			},
			wantErr:   true,
			wantErrIs: ErrInvalidParameter,
		},
		{
			name:       "bad opt: WithLookup",
			underlying: nil,
			args: args{
				deleteItems: createFn(),
				opt:         []Option{WithLookup(true)},
			},
			wantErr:   true,
			wantErrIs: ErrInvalidParameter,
		},
		{
			name:       "nil underlying",
			underlying: nil,
			args: args{
				deleteItems: createFn(),
			},
			wantErr:   true,
			wantErrIs: ErrInvalidParameter,
		},
		{
			name:       "empty items",
			underlying: db,
			args: args{
				deleteItems: []interface{}{},
			},
			wantErr:   true,
			wantErrIs: ErrInvalidParameter,
		},
		{
			name:       "nil items",
			underlying: db,
			args: args{
				deleteItems: nil,
			},
			wantErr:   true,
			wantErrIs: ErrInvalidParameter,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			rw := &Db{
				underlying: tt.underlying,
			}
			rowsDeleted, err := rw.DeleteItems(context.Background(), tt.args.deleteItems, tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
				if tt.wantErrIs != nil {
					assert.Truef(errors.Is(err, tt.wantErrIs), "unexpected error: %s", err.Error())
				}
				return
			}
			require.NoError(err)
			assert.Equal(tt.wantRowsDeleted, rowsDeleted)
			for _, item := range tt.args.deleteItems {
				u := db_test.AllocTestUser()
				u.PublicId = item.(*db_test.TestUser).PublicId
				err := rw.LookupByPublicId(context.Background(), &u)
				require.Error(err)
				require.Truef(errors.Is(err, ErrRecordNotFound), "found item %s that should be deleted", u.PublicId)
			}
			if tt.wantOplogId != "" {
				err = TestVerifyOplog(t, rw, tt.wantOplogId, WithOperation(oplog.OpType_OP_TYPE_DELETE), WithCreateNotBefore(10*time.Second))
				assert.NoError(err)
			}
			if tt.wantOplogMsgs {
				assert.Equal(len(tt.args.deleteItems), len(returnedMsgs))
				for _, m := range returnedMsgs {
					assert.Equal(m.OpType, oplog.OpType_OP_TYPE_DELETE)
				}
			}
		})
	}
}

func testUser(t *testing.T, conn *gorm.DB, name, email, phoneNumber string) *db_test.TestUser {
	t.Helper()
	require := require.New(t)

	publicId, err := base62.Random(20)
	require.NoError(err)
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
		require.NoError(err)
	}
	return u
}
func testCar(t *testing.T, conn *gorm.DB, name, model string, mpg int32) *db_test.TestCar {
	t.Helper()
	require := require.New(t)

	publicId, err := base62.Random(20)
	require.NoError(err)
	c := &db_test.TestCar{
		StoreTestCar: &db_test.StoreTestCar{
			PublicId: publicId,
			Name:     name,
			Model:    model,
			Mpg:      mpg,
		},
	}
	if conn != nil {
		err = conn.Create(c).Error
		require.NoError(err)
	}
	return c
}

func testId(t *testing.T) string {
	t.Helper()
	require := require.New(t)
	id, err := uuid.GenerateUUID()
	require.NoError(err)
	return id
}

func testScooter(t *testing.T, conn *gorm.DB, model string, mpg int32) *db_test.TestScooter {
	t.Helper()
	require := require.New(t)

	privateId, err := base62.Random(20)
	require.NoError(err)
	u := &db_test.TestScooter{
		StoreTestScooter: &db_test.StoreTestScooter{
			PrivateId: privateId,
			Model:     model,
			Mpg:       mpg,
		},
	}
	if conn != nil {
		err = conn.Create(u).Error
		require.NoError(err)
	}
	return u
}

func TestDb_LookupById(t *testing.T) {
	t.Parallel()
	db, _ := TestSetup(t, "postgres")
	scooter := testScooter(t, db, "", 0)
	user := testUser(t, db, "", "", "")
	type args struct {
		resourceWithIder interface{}
		opt              []Option
	}
	tests := []struct {
		name       string
		underlying *gorm.DB
		args       args
		wantErr    bool
		want       proto.Message
		wantIsErr  error
	}{
		{
			name:       "simple-private-id",
			underlying: db,
			args: args{
				resourceWithIder: scooter,
			},
			wantErr: false,
			want:    scooter,
		},
		{
			name:       "simple-public-id",
			underlying: db,
			args: args{
				resourceWithIder: user,
			},
			wantErr: false,
			want:    user,
		},
		{
			name:       "missing-public-id",
			underlying: db,
			args: args{
				resourceWithIder: &db_test.TestUser{
					StoreTestUser: &db_test.StoreTestUser{},
				},
			},
			wantErr:   true,
			wantIsErr: ErrInvalidParameter,
		},
		{
			name:       "missing-private-id",
			underlying: db,
			args: args{
				resourceWithIder: &db_test.TestScooter{
					StoreTestScooter: &db_test.StoreTestScooter{},
				},
			},
			wantErr:   true,
			wantIsErr: ErrInvalidParameter,
		},
		{
			name:       "not-an-ider",
			underlying: db,
			args: args{
				resourceWithIder: &db_test.NotIder{},
			},
			wantErr:   true,
			wantIsErr: ErrInvalidParameter,
		},
		{
			name:       "missing-underlying-db",
			underlying: nil,
			args: args{
				resourceWithIder: user,
			},
			wantErr:   true,
			wantIsErr: ErrInvalidParameter,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			rw := &Db{
				underlying: tt.underlying,
			}
			cloner, ok := tt.args.resourceWithIder.(db_test.Cloner)
			require.True(ok)
			cp := cloner.Clone()
			err := rw.LookupById(context.Background(), cp, tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
				require.True(errors.Is(err, tt.wantIsErr))
				return
			}
			require.NoError(err)
			assert.True(proto.Equal(tt.want, cp.(proto.Message)))
		})
	}
	t.Run("not-ptr", func(t *testing.T) {
		u := testUser(t, db, "", "", "")
		rw := &Db{
			underlying: db,
		}
		err := rw.LookupById(context.Background(), *u)
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrInvalidParameter))
	})
}

func TestDb_GetTicket(t *testing.T) {
	db, _ := TestSetup(t, "postgres")
	type notReplayable struct{}
	tests := []struct {
		name          string
		underlying    *gorm.DB
		aggregateType interface{}
		wantErr       bool
		wantErrIs     error
	}{
		{
			name:          "simple",
			underlying:    db,
			aggregateType: &db_test.TestUser{},
			wantErr:       false,
		},
		{
			name:          "not-replayable",
			underlying:    db,
			aggregateType: &notReplayable{},
			wantErr:       true,
			wantErrIs:     ErrInvalidParameter,
		},
		{
			name:          "nil-aggregate-type",
			underlying:    db,
			aggregateType: nil,
			wantErr:       true,
			wantErrIs:     ErrInvalidParameter,
		},
		{
			name:          "no-underlying",
			underlying:    nil,
			aggregateType: &db_test.TestUser{},
			wantErr:       true,
			wantErrIs:     ErrInvalidParameter,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			rw := &Db{
				underlying: tt.underlying,
			}
			got, err := rw.GetTicket(tt.aggregateType)
			if tt.wantErr {
				require.Error(err)
				if tt.wantErrIs != nil {
					assert.Truef(errors.Is(err, tt.wantErrIs), "unexpected error type: %s", err.Error())
				}
				return
			}
			require.NoError(err)
			assert.NotEmpty(got.Name)
			assert.NotEmpty(got.Version)
			assert.NotEmpty(got.CreateTime)
			assert.NotEmpty(got.UpdateTime)
		})
	}
}

func TestDb_WriteOplogEntryWith(t *testing.T) {
	db, _ := TestSetup(t, "postgres")
	w := Db{underlying: db}

	ticket, err := w.GetTicket(&db_test.TestUser{})
	require.NoError(t, err)

	id, err := uuid.GenerateUUID()
	assert.NoError(t, err)
	user, err := db_test.NewTestUser()
	assert.NoError(t, err)
	user.Name = "foo-" + id
	createMsg := oplog.Message{}
	err = w.Create(
		context.Background(),
		user,
		NewOplogMsg(&createMsg),
	)
	require.NoError(t, err)
	metadata := oplog.Metadata{
		"resource-public-id": []string{user.PublicId},
	}

	type args struct {
		wrapper  wrapping.Wrapper
		ticket   *store.Ticket
		metadata oplog.Metadata
		msgs     []*oplog.Message
		opt      []Option
	}
	tests := []struct {
		name            string
		underlying      *gorm.DB
		args            args
		wantErr         bool
		wantErrIs       error
		wantErrContains string
	}{
		{
			name:       "valid",
			underlying: db,
			args: args{
				wrapper:  TestWrapper(t),
				ticket:   ticket,
				metadata: metadata,
				msgs:     []*oplog.Message{&createMsg},
			},
			wantErr: false,
		},
		{
			name:       "valid-multiple",
			underlying: db,
			args: args{
				wrapper:  TestWrapper(t),
				ticket:   ticket,
				metadata: metadata,
				msgs:     []*oplog.Message{&createMsg, &createMsg},
			},
			wantErr: false,
		},
		{
			name:       "missing-ticket",
			underlying: db,
			args: args{
				wrapper:  TestWrapper(t),
				ticket:   nil,
				metadata: metadata,
				msgs:     []*oplog.Message{&createMsg},
			},
			wantErr:   true,
			wantErrIs: ErrInvalidParameter,
		},
		{
			name:       "missing-db",
			underlying: nil,
			args: args{
				wrapper:  TestWrapper(t),
				ticket:   ticket,
				metadata: metadata,
				msgs:     []*oplog.Message{&createMsg},
			},
			wantErr:   true,
			wantErrIs: ErrInvalidParameter,
		},
		{
			name:       "missing-wrapper",
			underlying: db,
			args: args{
				wrapper:  nil,
				ticket:   ticket,
				metadata: metadata,
				msgs:     []*oplog.Message{&createMsg},
			},
			wantErr:   true,
			wantErrIs: ErrInvalidParameter,
		},
		{
			name:       "nil-metadata",
			underlying: db,
			args: args{
				wrapper:  TestWrapper(t),
				ticket:   ticket,
				metadata: nil,
				msgs:     []*oplog.Message{&createMsg},
			},
			wantErr:   true,
			wantErrIs: ErrInvalidParameter,
		},
		{
			name:       "empty-metadata",
			underlying: db,
			args: args{
				wrapper:  TestWrapper(t),
				ticket:   ticket,
				metadata: oplog.Metadata{},
				msgs:     []*oplog.Message{&createMsg},
			},
			wantErr:   true,
			wantErrIs: ErrInvalidParameter,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			rw := &Db{
				underlying: tt.underlying,
			}
			err := rw.WriteOplogEntryWith(context.Background(), tt.args.wrapper, tt.args.ticket, tt.args.metadata, tt.args.msgs, tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
				if tt.wantErrIs != nil {
					assert.Truef(errors.Is(err, tt.wantErrIs), "unexpected error %s", err.Error())
				}
				if tt.wantErrContains != "" {
					assert.Contains(err.Error(), tt.wantErrContains)
				}
				return
			}
			require.NoError(err)
		})
	}
}

func TestClear_InputTypes(t *testing.T) {
	type Z struct {
		F string
	}

	var nilZ *Z
	s := "test-string"

	type args struct {
		v interface{}
		f []string
		d int
	}

	var tests = []struct {
		name string
		args args
		want interface{}
		err  error
	}{
		{
			name: "nil",
			args: args{
				v: nil,
				f: []string{"field"},
				d: 1,
			},
			err: ErrInvalidParameter,
		},
		{
			name: "string",
			args: args{
				v: "blank",
				f: []string{"field"},
				d: 1,
			},
			err: ErrInvalidParameter,
		},
		{
			name: "pointer-to-nil-struct",
			args: args{
				v: nilZ,
				f: []string{"field"},
				d: 1,
			},
			err: ErrInvalidParameter,
		},
		{
			name: "pointer-to-string",
			args: args{
				v: &s,
				f: []string{"field"},
				d: 1,
			},
			err: ErrInvalidParameter,
		},
		{
			name: "not-pointer",
			args: args{
				v: Z{
					F: "foo",
				},
				f: []string{"field"},
				d: 1,
			},
			err: ErrInvalidParameter,
		},
		{
			name: "map",
			args: args{
				v: map[string]int{
					"A": 31,
					"B": 34,
				},
				f: []string{"field"},
				d: 1,
			},
			err: ErrInvalidParameter,
		},
		{
			name: "pointer-to-struct",
			args: args{
				v: &Z{
					F: "foo",
				},
				f: []string{"field"},
				d: 1,
			},
			want: &Z{
				F: "foo",
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			input := tt.args.v
			err := Clear(input, tt.args.f, tt.args.d)
			if tt.err != nil {
				assert.Error(err)
				return
			}
			require.NoError(err)
			assert.Equal(tt.want, input)
		})
	}
}

func TestClear_Structs(t *testing.T) {
	s := "test-string"

	type A struct{ F string }
	type B struct{ F *string }

	type AB struct {
		A A
		B *B
		F string

		IN io.Reader
		MP map[int]int
		SL []string
		AR [1]int
		CH chan int
		FN func()
	}

	type AFB struct {
		F A
		B *B
	}

	type ABF struct {
		A A
		F *B
	}

	type C struct {
		F  string
		NF string
	}

	type EA struct {
		A
		M  string
		NF string
	}

	type EAP struct {
		*A
		M  string
		NF string
	}

	type DEA struct {
		EA
		F string
	}

	type DEAP struct {
		*EAP
		F string
	}

	type args struct {
		v interface{}
		f []string
		d int
	}
	var tests = []struct {
		name string
		args args
		want interface{}
	}{
		{
			name: "blank-A",
			args: args{
				v: &A{},
				f: []string{"F"},
				d: 1,
			},
			want: &A{},
		},
		{
			name: "clear-A",
			args: args{
				v: &A{"clear"},
				f: []string{"F"},
				d: 1,
			},
			want: &A{},
		},
		{
			name: "clear-B",
			args: args{
				v: &B{&s},
				f: []string{"F"},
				d: 1,
			},
			want: &B{},
		},
		{
			name: "clear-C",
			args: args{
				v: &C{"clear", "notclear"},
				f: []string{"F"},
				d: 1,
			},
			want: &C{"", "notclear"},
		},
		{
			name: "shallow-clear-AB",
			args: args{
				v: &AB{
					A: A{"notclear"},
					B: &B{&s},
					F: "clear",
				},
				f: []string{"F"},
				d: 1,
			},
			want: &AB{
				A: A{"notclear"},
				B: &B{&s},
				F: "",
			},
		},
		{
			name: "deep-clear-AB",
			args: args{
				v: &AB{
					A: A{"clear"},
					B: &B{&s},
					F: "clear",
				},
				f: []string{"F"},
				d: 2,
			},
			want: &AB{
				A: A{""},
				B: &B{},
				F: "",
			},
		},
		{
			name: "clear-AFB",
			args: args{
				v: &AFB{
					F: A{"clear"},
					B: &B{&s},
				},
				f: []string{"F"},
				d: 2,
			},
			want: &AFB{
				F: A{""},
				B: &B{},
			},
		},
		{
			name: "clear-ABF",
			args: args{
				v: &ABF{
					A: A{"clear"},
					F: &B{&s},
				},
				f: []string{"F"},
				d: 2,
			},
			want: &ABF{
				A: A{""},
				F: nil,
			},
		},
		{
			name: "embedded-struct",
			args: args{
				v: &EA{
					A:  A{"clear"},
					M:  "clear",
					NF: "notclear",
				},
				f: []string{"F", "M"},
				d: 2,
			},
			want: &EA{
				A:  A{""},
				M:  "",
				NF: "notclear",
			},
		},
		{
			name: "embedded-struct-pointer",
			args: args{
				v: &EAP{
					A:  &A{"clear"},
					M:  "clear",
					NF: "notclear",
				},
				f: []string{"F", "M"},
				d: 2,
			},
			want: &EAP{
				A:  &A{""},
				M:  "",
				NF: "notclear",
			},
		},
		{
			name: "embedded-struct-pointer-extra-depth",
			args: args{
				v: &EAP{
					A:  &A{"clear"},
					M:  "clear",
					NF: "notclear",
				},
				f: []string{"F", "M"},
				d: 12,
			},
			want: &EAP{
				A:  &A{""},
				M:  "",
				NF: "notclear",
			},
		},
		{
			name: "deep-embedded-struct",
			args: args{
				v: &DEA{
					EA: EA{
						A:  A{"clear"},
						M:  "clear",
						NF: "notclear",
					},
					F: "clear",
				},
				f: []string{"F", "M"},
				d: 3,
			},
			want: &DEA{
				EA: EA{
					A:  A{""},
					M:  "",
					NF: "notclear",
				},
				F: "",
			},
		},
		{
			name: "deep-embedded-struct-pointer",
			args: args{
				v: &DEAP{
					EAP: &EAP{
						A:  &A{"clear"},
						M:  "clear",
						NF: "notclear",
					},
					F: "clear",
				},
				f: []string{"F", "M"},
				d: 3,
			},
			want: &DEAP{
				EAP: &EAP{
					A:  &A{""},
					M:  "",
					NF: "notclear",
				},
				F: "",
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			input := tt.args.v
			err := Clear(input, tt.args.f, tt.args.d)
			assert.NotEmpty(s)
			require.NoError(err)
			assert.Equal(tt.want, input)
		})
	}
}

func TestClear_SetFieldsToNil(t *testing.T) {
	type P struct{ F *string }
	type A struct{ F string }

	type EA struct {
		A
		M  string
		NF string
	}

	type EAP struct {
		*A
		M  string
		NF string
	}

	type DEA struct {
		EA
		F string
	}

	type DEAP struct {
		*EAP
		F string
	}

	type args struct {
		v interface{}
		f []string
	}
	var tests = []struct {
		name string
		args args
		want interface{}
	}{
		{
			name: "dont-panic",
			args: args{
				v: P{},
				f: []string{"F"},
			},
			want: P{},
		},
		{
			name: "deep-embedded-struct",
			args: args{
				v: &DEA{
					EA: EA{
						A:  A{"notclear"},
						M:  "clear",
						NF: "notclear",
					},
					F: "clear",
				},
				f: []string{"F", "M"},
			},
			want: &DEA{
				EA: EA{
					A:  A{"notclear"},
					M:  "",
					NF: "notclear",
				},
				F: "",
			},
		},
		{
			name: "deep-embedded-struct-pointer",
			args: args{
				v: &DEAP{
					EAP: &EAP{
						A:  &A{"notclear"},
						M:  "clear",
						NF: "notclear",
					},
					F: "clear",
				},
				f: []string{"F", "M"},
			},
			want: &DEAP{
				EAP: &EAP{
					A:  &A{"notclear"},
					M:  "",
					NF: "notclear",
				},
				F: "",
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			input := tt.args.v
			require.NotPanics(func() {
				setFieldsToNil(input, tt.args.f)
			})
			assert.Equal(tt.want, input)
		})
	}
}

func TestDb_oplogMsgsForItems(t *testing.T) {
	t.Parallel()

	// underlying isn't used at this point, so it can just be nil
	rw := Db{underlying: nil}
	var users []interface{}
	var wantUsrMsgs []*oplog.Message
	for i := 0; i < 5; i++ {
		publicId, err := base62.Random(20)
		require.NoError(t, err)
		u := &db_test.TestUser{StoreTestUser: &db_test.StoreTestUser{PublicId: publicId}}
		users = append(users, u)
		wantUsrMsgs = append(
			wantUsrMsgs,
			&oplog.Message{
				Message:  users[i].(proto.Message),
				TypeName: u.TableName(),
				OpType:   oplog.OpType_OP_TYPE_CREATE,
			},
		)
	}

	publicId, err := base62.Random(20)
	require.NoError(t, err)
	mixed := []interface{}{
		&db_test.TestUser{StoreTestUser: &db_test.StoreTestUser{PublicId: publicId}},
		&db_test.TestCar{StoreTestCar: &db_test.StoreTestCar{PublicId: publicId}},
	}

	type args struct {
		opType OpType
		opts   Options
		items  []interface{}
	}
	tests := []struct {
		name      string
		args      args
		want      []*oplog.Message
		wantErr   bool
		wantIsErr error
	}{
		{
			name: "valid",
			args: args{
				opType: CreateOp,
				items:  users,
			},
			wantErr: false,
			want:    wantUsrMsgs,
		},
		{
			name: "nil items",
			args: args{
				opType: CreateOp,
				items:  nil,
			},
			wantErr:   true,
			wantIsErr: ErrInvalidParameter,
		},
		{
			name: "zero items",
			args: args{
				opType: CreateOp,
				items:  []interface{}{},
			},
			wantErr:   true,
			wantIsErr: ErrInvalidParameter,
		},
		{
			name: "mixed items",
			args: args{
				opType: CreateOp,
				items:  mixed,
			},
			wantErr:   true,
			wantIsErr: ErrInvalidParameter,
		},
		{
			name: "bad op",
			args: args{
				opType: UnknownOp,
				items:  users,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := rw.oplogMsgsForItems(context.Background(), tt.args.opType, tt.args.opts, tt.args.items)
			if tt.wantErr {
				require.Error(err)
				if tt.wantIsErr != nil {
					assert.Truef(errors.Is(err, tt.wantIsErr), "unexpected error %s", err.Error())
				}
				return
			}
			require.NoError(err)
			assert.Equal(tt.want, got)
		})
	}
}

func TestDb_lookupAfterWrite(t *testing.T) {
	t.Parallel()
	db, _ := TestSetup(t, "postgres")
	scooter := testScooter(t, db, "", 0)
	user := testUser(t, db, "", "", "")
	type args struct {
		resourceWithIder interface{}
		opt              []Option
	}
	tests := []struct {
		name       string
		underlying *gorm.DB
		args       args
		wantErr    bool
		want       proto.Message
		wantIsErr  error
	}{
		{
			name:       "simple-private-id",
			underlying: db,
			args: args{
				resourceWithIder: scooter,
				opt:              []Option{WithLookup(true)},
			},
			wantErr: false,
			want:    scooter,
		},
		{
			name:       "simple-public-id",
			underlying: db,
			args: args{
				resourceWithIder: user,
				opt:              []Option{WithLookup(true)},
			},
			wantErr: false,
			want:    user,
		},
		{
			name:       "no-lookup-private-id",
			underlying: db,
			args: args{
				resourceWithIder: scooter,
				opt:              []Option{WithLookup(false)},
			},
			wantErr: false,
			want:    nil,
		},
		{
			name:       "no-lookup-public-id",
			underlying: db,
			args: args{
				resourceWithIder: user,
				opt:              []Option{WithLookup(false)},
			},
			wantErr: false,
			want:    nil,
		},
		{
			name:       "not-an-ider",
			underlying: db,
			args: args{
				resourceWithIder: &db_test.NotIder{},
				opt:              []Option{WithLookup(true)},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			rw := &Db{
				underlying: tt.underlying,
			}
			cloner, ok := tt.args.resourceWithIder.(db_test.Cloner)
			require.True(ok)
			cp := cloner.Clone()
			err := rw.lookupAfterWrite(context.Background(), cp, tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
				return
			}
			require.NoError(err)
			if tt.want != nil {
				assert.True(proto.Equal(tt.want, cp.(proto.Message)))
			}
		})
	}
}
