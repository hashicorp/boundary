package oplog

import (
	reflect "reflect"
	"testing"

	"google.golang.org/protobuf/proto"
	"gotest.tools/assert"

	"github.com/hashicorp/watchtower/internal/oplog/oplog_test"
)

// Test_Queue provides basic tests for the Queue type
func Test_Queue(t *testing.T) {
	t.Parallel()
	types, err := NewTypeCatalog(
		Type{new(oplog_test.TestUser), "user"},
		Type{new(oplog_test.TestCar), "car"},
		Type{new(oplog_test.TestRental), "rental"},
	)
	assert.NilError(t, err)
	queue := Queue{Catalog: types}

	user := &oplog_test.TestUser{
		Id:          1,
		Name:        "Alice",
		PhoneNumber: "867-5309",
		Email:       "alice@bob.com",
	}
	car := &oplog_test.TestCar{
		Id:    2,
		Model: "Jeep",
		Mpg:   25,
	}
	rental := &oplog_test.TestRental{
		UserId: 1,
		CarId:  2,
	}

	userUpdate := &oplog_test.TestUser{
		Id:    1,
		Name:  "bob",
		Email: "bob@alice.com",
	}
	t.Run("add/remove", func(t *testing.T) {
		err = queue.Add(user, "user", OpType_OP_TYPE_CREATE)
		assert.NilError(t, err)
		err = queue.Add(car, "car", OpType_OP_TYPE_CREATE)
		assert.NilError(t, err)
		err = queue.Add(rental, "rental", OpType_OP_TYPE_CREATE)
		assert.NilError(t, err)
		err = queue.Add(userUpdate, "user", OpType_OP_TYPE_UPDATE, WithFieldMaskPaths([]string{"Name", "Email"}))
		assert.NilError(t, err)

		queuedUser, ty, fm, err := queue.Remove()
		assert.NilError(t, err)
		assert.Assert(t, proto.Equal(user, queuedUser))
		assert.Assert(t, ty == OpType_OP_TYPE_CREATE)
		assert.Assert(t, fm == nil)

		queuedCar, ty, fm, err := queue.Remove()
		assert.NilError(t, err)
		assert.Assert(t, proto.Equal(car, queuedCar))
		assert.Assert(t, ty == OpType_OP_TYPE_CREATE)
		assert.Assert(t, fm == nil)

		queuedRental, ty, fm, err := queue.Remove()
		assert.NilError(t, err)
		assert.Assert(t, proto.Equal(rental, queuedRental))
		assert.Assert(t, ty == OpType_OP_TYPE_CREATE)
		assert.Assert(t, fm == nil)

		queuedUserUpdate, ty, fm, err := queue.Remove()
		assert.NilError(t, err)
		assert.Assert(t, proto.Equal(userUpdate, queuedUserUpdate))
		assert.Assert(t, ty == OpType_OP_TYPE_UPDATE)
		assert.Assert(t, reflect.DeepEqual(fm, []string{"Name", "Email"}))
	})
	t.Run("valid with nil type catalog", func(t *testing.T) {
		queue := Queue{}
		assert.NilError(t, queue.Add(user, "user", OpType_OP_TYPE_CREATE))
	})
	t.Run("error with nil type catalog", func(t *testing.T) {
		queue := Queue{}
		_, _, _, err := queue.Remove()
		assert.Check(t, err != nil)
		assert.Equal(t, err.Error(), "remove Catalog is nil")
	})
	t.Run("not replayable", func(t *testing.T) {
		u := &oplog_test.TestNonReplayableUser{
			Name:        "Alice",
			PhoneNumber: "867-5309",
			Email:       "alice@bob.com",
		}
		err = queue.Add(u, "user", OpType_CREATE_OP)
		assert.Check(t, err != nil)
		assert.Equal(t, err.Error(), "error *oplog_test.TestNonReplayableUser is not a ReplayableMessage")
	})
	t.Run("nil message", func(t *testing.T) {
		err = queue.Add(nil, "user", OpType_CREATE_OP)
		assert.Check(t, err != nil)
		assert.Equal(t, err.Error(), "error <nil> is not a ReplayableMessage")
	})

}
