package oplog

import (
	"testing"

	"github.com/hashicorp/boundary/internal/oplog/oplog_test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

// Test_Queue provides basic tests for the Queue type
func Test_Queue(t *testing.T) {
	t.Parallel()
	types, err := NewTypeCatalog(
		Type{new(oplog_test.TestUser), "user"},
		Type{new(oplog_test.TestCar), "car"},
		Type{new(oplog_test.TestRental), "rental"},
	)
	require.NoError(t, err)
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

	userNilUpdate := &oplog_test.TestUser{
		Id:   1,
		Name: "bob",
	}
	t.Run("add/remove", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		err = queue.Add(user, "user", OpType_OP_TYPE_CREATE)
		require.NoError(err)
		err = queue.Add(car, "car", OpType_OP_TYPE_CREATE)
		require.NoError(err)
		err = queue.Add(rental, "rental", OpType_OP_TYPE_CREATE)
		require.NoError(err)
		err = queue.Add(userUpdate, "user", OpType_OP_TYPE_UPDATE, WithFieldMaskPaths([]string{"Name", "Email"}))
		require.NoError(err)
		err = queue.Add(userNilUpdate, "user", OpType_OP_TYPE_UPDATE, WithFieldMaskPaths([]string{"Name"}), WithSetToNullPaths([]string{"Email"}))
		require.NoError(err)

		queuedUser, ty, fm, nm, err := queue.Remove()
		require.NoError(err)
		assert.True(proto.Equal(user, queuedUser))
		assert.Equal(ty, OpType_OP_TYPE_CREATE)
		assert.Nil(fm)
		assert.Nil(nm)

		queuedCar, ty, fm, nm, err := queue.Remove()
		require.NoError(err)
		assert.True(proto.Equal(car, queuedCar))
		assert.Equal(ty, OpType_OP_TYPE_CREATE)
		assert.Nil(fm)
		assert.Nil(nm)

		queuedRental, ty, fm, nm, err := queue.Remove()
		require.NoError(err)
		assert.True(proto.Equal(rental, queuedRental))
		assert.Equal(ty, OpType_OP_TYPE_CREATE)
		assert.Nil(fm)
		assert.Nil(nm)

		queuedUserUpdate, ty, fm, nm, err := queue.Remove()
		require.NoError(err)
		assert.True(proto.Equal(userUpdate, queuedUserUpdate))
		assert.Equal(ty, OpType_OP_TYPE_UPDATE)
		assert.Equal(fm, []string{"Name", "Email"})
		assert.Nil(nm)

		queuedUserNilUpdate, ty, fm, nm, err := queue.Remove()
		require.NoError(err)
		assert.True(proto.Equal(userNilUpdate, queuedUserNilUpdate))
		assert.Equal(ty, OpType_OP_TYPE_UPDATE)
		assert.Equal(fm, []string{"Name"})
		assert.Equal(nm, []string{"Email"})
	})
	t.Run("valid with nil type catalog", func(t *testing.T) {
		require := require.New(t)
		queue := Queue{}
		require.NoError(queue.Add(user, "user", OpType_OP_TYPE_CREATE))
	})
	t.Run("error with nil type catalog", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		queue := Queue{}
		_, _, _, _, err = queue.Remove()
		require.Error(err)
		assert.Equal("oplog.(Queue).Remove: nil catalog: parameter violation: error #100", err.Error())
	})
	t.Run("not replayable", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		u := &oplog_test.TestNonReplayableUser{
			Name:        "Alice",
			PhoneNumber: "867-5309",
			Email:       "alice@bob.com",
		}
		err = queue.Add(u, "user", OpType_OP_TYPE_CREATE)
		require.Error(err)
		assert.Equal("oplog.(Queue).Add: *oplog_test.TestNonReplayableUser is not a replayable message: parameter violation: error #100", err.Error())
	})
	t.Run("nil message", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		err = queue.Add(nil, "user", OpType_OP_TYPE_CREATE)
		require.Error(err)
		assert.Equal("oplog.(Queue).Add: <nil> is not a replayable message: parameter violation: error #100", err.Error())
	})
	t.Run("missing both field mask and null paths for update", func(t *testing.T) {
		require.Error(t, queue.Add(userUpdate, "user", OpType_OP_TYPE_UPDATE))
	})
	t.Run("intersecting field masks and null paths", func(t *testing.T) {
		require.Error(t, queue.Add(userNilUpdate, "user", OpType_OP_TYPE_UPDATE, WithFieldMaskPaths([]string{"Name"}), WithSetToNullPaths([]string{"Name"})))
	})
}
