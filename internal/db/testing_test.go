package db

import (
	"context"
	"testing"
	"time"

	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/watchtower/internal/db/db_test"
	"github.com/hashicorp/watchtower/internal/oplog"
	"github.com/stretchr/testify/assert"
)

func Test_Utils(t *testing.T) {
	t.Parallel()
	_, _ = TestSetup(t, "postgres")
	t.Run("nothing", func(t *testing.T) {

	})
}

func TestVerifyOplogEntry(t *testing.T) {
	db, _ := TestSetup(t, "postgres")
	assert := assert.New(t)

	t.Run("valid", func(t *testing.T) {
		rw := Db{underlying: db}
		id, err := uuid.GenerateUUID()
		assert.NoError(err)
		user, err := db_test.NewTestUser()
		assert.NoError(err)
		user.Name = "foo-" + id
		err = rw.Create(
			context.Background(),
			user,
			WithOplog(
				TestWrapper(t),
				oplog.Metadata{
					"op-type":            []string{oplog.OpType_OP_TYPE_CREATE.String()},
					"resource-public-id": []string{user.GetPublicId()},
				}),
		)
		assert.NoError(err)
		assert.NotZero(user.Id)

		foundUser, err := db_test.NewTestUser()
		assert.NoError(err)
		foundUser.PublicId = user.PublicId
		err = rw.LookupByPublicId(context.Background(), foundUser)
		assert.NoError(err)
		assert.Equal(foundUser.Id, user.Id)
		err = TestVerifyOplog(t, &rw, user.PublicId, WithOperation(oplog.OpType_OP_TYPE_CREATE), WithCreateNotBefore(5*time.Second))
		assert.NoError(err)
	})
	t.Run("should-fail", func(t *testing.T) {
		rw := Db{underlying: db}
		id, err := uuid.GenerateUUID()
		assert.NoError(err)
		err = TestVerifyOplog(t, &rw, id)
		assert.Error(err)
	})
}

func Test_getTestOpts(t *testing.T) {
	t.Parallel()
	assert := assert.New(t)
	t.Run("WithOperation", func(t *testing.T) {
		opts := getTestOpts(WithOperation(oplog.OpType_OP_TYPE_CREATE))
		testOpts := getDefaultTestOptions()
		testOpts.withOperation = oplog.OpType_OP_TYPE_CREATE
		assert.Equal(opts, testOpts)
	})
	t.Run("WithCreateNotBefore", func(t *testing.T) {
		nbfSecs := 10
		opts := getTestOpts(WithCreateNotBefore(time.Second * 10))
		testOpts := getDefaultTestOptions()
		testOpts.withCreateNotBefore = &nbfSecs
		assert.Equal(opts, testOpts)
	})
}

func TestWithCreateNotBefore(t *testing.T) {
	type args struct {
		nbfDuration time.Duration
	}
	tests := []struct {
		name string
		args args
		want int
	}{
		{
			name: "0 seconds",
			args: args{nbfDuration: 0},
			want: 0,
		},
		{
			name: "1 seconds",
			args: args{nbfDuration: time.Millisecond * 1900},
			want: 1,
		},
		{
			name: "2 seconds",
			args: args{nbfDuration: time.Millisecond * 2100},
			want: 2,
		},
		{
			name: "60 seconds",
			args: args{nbfDuration: time.Minute * 1},
			want: 60,
		},
	}
	assert := assert.New(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := getTestOpts(WithCreateNotBefore(tt.args.nbfDuration))
			testOpts := getDefaultTestOptions()
			testOpts.withCreateNotBefore = &tt.want
			assert.Equal(opts, testOpts)
		})
	}
}
