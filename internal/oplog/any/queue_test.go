package any

import (
	"testing"

	"github.com/hashicorp/watchtower/internal/oplog/oplog_test"
	"github.com/matryer/is"
	"google.golang.org/protobuf/proto"
)

// Test_Queue provides basic tests for the Queue type
func Test_Queue(t *testing.T) {
	t.Parallel()
	is := is.New(t)
	types, err := NewTypeCatalog(
		Type{new(oplog_test.TestUser), "user"},
		Type{new(oplog_test.TestCar), "car"},
		Type{new(oplog_test.TestRental), "rental"},
	)
	is.NoErr(err)
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

	err = queue.Add(user, "user", OpType_CreateOp)
	is.NoErr(err)
	err = queue.Add(car, "car", OpType_CreateOp)
	is.NoErr(err)
	err = queue.Add(rental, "rental", OpType_CreateOp)
	is.NoErr(err)

	queuedUser, ty, _, err := queue.Remove()
	is.NoErr(err)
	is.True(proto.Equal(user, queuedUser))
	is.True(ty == OpType_CreateOp)

	queuedCar, ty, _, err := queue.Remove()
	is.NoErr(err)
	is.True(proto.Equal(car, queuedCar))
	is.True(ty == OpType_CreateOp)

	queuedRental, ty, _, err := queue.Remove()
	is.NoErr(err)
	is.True(proto.Equal(rental, queuedRental))
	is.True(ty == OpType_CreateOp)
}
