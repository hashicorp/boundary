package oplog

import (
	reflect "reflect"
	"testing"

	"github.com/hashicorp/watchtower/internal/oplog/oplog_test"
	"google.golang.org/protobuf/proto"
	"gotest.tools/assert"
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

	err = queue.Add(user, "user", OpType_CREATE_OP)
	assert.NilError(t, err)
	err = queue.Add(car, "car", OpType_CREATE_OP)
	assert.NilError(t, err)
	err = queue.Add(rental, "rental", OpType_CREATE_OP)
	assert.NilError(t, err)
	err = queue.Add(userUpdate, "user", OpType_UPDATE_OP, WithFieldMaskPaths([]string{"Name", "Email"}))
	assert.NilError(t, err)

	queuedUser, ty, fm, err := queue.Remove()
	assert.NilError(t, err)
	assert.Assert(t, proto.Equal(user, queuedUser))
	assert.Assert(t, ty == OpType_CREATE_OP)
	assert.Assert(t, fm == nil)

	queuedCar, ty, fm, err := queue.Remove()
	assert.NilError(t, err)
	assert.Assert(t, proto.Equal(car, queuedCar))
	assert.Assert(t, ty == OpType_CREATE_OP)
	assert.Assert(t, fm == nil)

	queuedRental, ty, fm, err := queue.Remove()
	assert.NilError(t, err)
	assert.Assert(t, proto.Equal(rental, queuedRental))
	assert.Assert(t, ty == OpType_CREATE_OP)
	assert.Assert(t, fm == nil)

	queuedUserUpdate, ty, fm, err := queue.Remove()
	assert.NilError(t, err)
	assert.Assert(t, proto.Equal(userUpdate, queuedUserUpdate))
	assert.Assert(t, ty == OpType_UPDATE_OP)
	assert.Assert(t, reflect.DeepEqual(fm, []string{"Name", "Email"}))
}
