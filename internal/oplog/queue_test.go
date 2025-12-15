// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package oplog

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/oplog/oplog_test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

// Test_Queue provides basic tests for the Queue type
func Test_Queue(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	types, err := NewTypeCatalog(testCtx,
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
		err = queue.add(testCtx, user, "user", OpType_OP_TYPE_CREATE)
		require.NoError(err)
		err = queue.add(testCtx, car, "car", OpType_OP_TYPE_CREATE)
		require.NoError(err)
		err = queue.add(testCtx, rental, "rental", OpType_OP_TYPE_CREATE)
		require.NoError(err)
		err = queue.add(testCtx, userUpdate, "user", OpType_OP_TYPE_UPDATE, WithFieldMaskPaths([]string{"Name", "Email"}))
		require.NoError(err)
		err = queue.add(testCtx, userNilUpdate, "user", OpType_OP_TYPE_UPDATE, WithFieldMaskPaths([]string{"Name"}), WithSetToNullPaths([]string{"Email"}))
		require.NoError(err)

		queuedUser, err := queue.remove(testCtx)
		require.NoError(err)
		assert.True(proto.Equal(user, queuedUser.msg))
		assert.Equal(queuedUser.opType, OpType_OP_TYPE_CREATE)
		assert.Nil(queuedUser.fieldMask)
		assert.Nil(queuedUser.setToNullPaths)

		queuedCar, err := queue.remove(testCtx)
		require.NoError(err)
		assert.True(proto.Equal(car, queuedCar.msg))
		assert.Equal(queuedCar.opType, OpType_OP_TYPE_CREATE)
		assert.Nil(queuedCar.fieldMask)
		assert.Nil(queuedCar.setToNullPaths)

		queuedRental, err := queue.remove(testCtx)
		require.NoError(err)
		assert.True(proto.Equal(rental, queuedRental.msg))
		assert.Equal(queuedRental.opType, OpType_OP_TYPE_CREATE)
		assert.Nil(queuedRental.fieldMask)
		assert.Nil(queuedRental.setToNullPaths)

		queuedUserUpdate, err := queue.remove(testCtx)
		require.NoError(err)
		assert.True(proto.Equal(userUpdate, queuedUserUpdate.msg))
		assert.Equal(queuedUserUpdate.opType, OpType_OP_TYPE_UPDATE)
		assert.Equal(queuedUserUpdate.fieldMask, []string{"Name", "Email"})
		assert.Nil(queuedUserUpdate.setToNullPaths)

		queuedUserNilUpdate, err := queue.remove(testCtx)
		require.NoError(err)
		assert.True(proto.Equal(userNilUpdate, queuedUserNilUpdate.msg))
		assert.Equal(queuedUserNilUpdate.opType, OpType_OP_TYPE_UPDATE)
		assert.Equal(queuedUserNilUpdate.fieldMask, []string{"Name"})
		assert.Equal(queuedUserNilUpdate.setToNullPaths, []string{"Email"})
	})
	t.Run("valid with nil type catalog", func(t *testing.T) {
		require := require.New(t)
		queue := Queue{}
		require.NoError(queue.add(testCtx, user, "user", OpType_OP_TYPE_CREATE))
	})
	t.Run("error with nil type catalog", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		queue := Queue{}
		_, err = queue.remove(testCtx)
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
		err = queue.add(testCtx, u, "user", OpType_OP_TYPE_CREATE)
		require.Error(err)
		assert.Equal("oplog.(Queue).Add: *oplog_test.TestNonReplayableUser is not a replayable message: parameter violation: error #100", err.Error())
	})
	t.Run("nil message", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		err = queue.add(testCtx, nil, "user", OpType_OP_TYPE_CREATE)
		require.Error(err)
		assert.Equal("oplog.(Queue).Add: <nil> is not a replayable message: parameter violation: error #100", err.Error())
	})
	t.Run("missing both field mask and null paths for update", func(t *testing.T) {
		require.Error(t, queue.add(testCtx, userUpdate, "user", OpType_OP_TYPE_UPDATE))
	})
	t.Run("intersecting field masks and null paths", func(t *testing.T) {
		require.Error(t, queue.add(testCtx, userNilUpdate, "user", OpType_OP_TYPE_UPDATE, WithFieldMaskPaths([]string{"Name"}), WithSetToNullPaths([]string{"Name"})))
	})
}
