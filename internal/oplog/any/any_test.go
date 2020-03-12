package any

import (
	"bytes"
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/hashicorp/watchtower/internal/oplog/oplog_test"
	"github.com/matryer/is"
)

// Test_QueueBuffer provides basic tests for the QueueBuffer type
func Test_QueueBuffer(t *testing.T) {
	t.Parallel()
	is := is.New(t)
	b := QueueBuffer{}

	_, err := b.Write([]byte("bye"))
	is.NoErr(err)
	is.True(b.Len() == len([]byte("bye")))

	_, err = b.Write([]byte("hello"))
	is.NoErr(err)
	is.True(b.Len() == len([]byte("bye"))+len([]byte("hello")))

	bye := make([]byte, 3)
	_, err = b.Read(bye)
	is.NoErr(err)
	is.True(bytes.Equal(bye, []byte("bye")))

	hello := b.Next(len([]byte("hello")))
	is.NoErr(err)
	is.True(bytes.Equal(hello, []byte("hello")))

	t.Log(string(hello))
	t.Log(string(bye))
}

// Test_Queue provides basic tests for the Queue type
func Test_Queue(t *testing.T) {
	t.Parallel()
	is := is.New(t)
	types, err := NewTypeCatalog(
		new(oplog_test.TestUser),
		new(oplog_test.TestCar),
		new(oplog_test.TestRental),
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

	err = queue.Add(user, OpType_CreateOp)
	is.NoErr(err)
	err = queue.Add(car, OpType_CreateOp)
	is.NoErr(err)
	err = queue.Add(rental, OpType_CreateOp)
	is.NoErr(err)

	queuedUser, ty, err := queue.Remove()
	is.NoErr(err)
	is.True(proto.Equal(user, queuedUser))
	is.True(ty == OpType_CreateOp)

	queuedCar, ty, err := queue.Remove()
	is.NoErr(err)
	is.True(proto.Equal(car, queuedCar))
	is.True(ty == OpType_CreateOp)

	queuedRental, ty, err := queue.Remove()
	is.NoErr(err)
	is.True(proto.Equal(rental, queuedRental))
	is.True(ty == OpType_CreateOp)
}
