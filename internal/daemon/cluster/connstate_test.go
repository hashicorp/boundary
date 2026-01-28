// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package cluster

import (
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
)

type testConn struct {
	net.Conn
	st *structpb.Struct
}

func (c *testConn) ClientState() *structpb.Struct {
	return c.st
}

func TestWorkerConnectionInfo(t *testing.T) {
	connInfo := []*WorkerConnectionInfo{
		{WorkerId: "something"},
		{UpstreamAddress: "something"},
		{BoundaryVersion: "something"},
		{Name: "something"},
		{Description: "something"},
		{PublicAddr: "something"},
		{OperationalState: "something"},
		{
			WorkerId:         "something",
			UpstreamAddress:  "something else",
			BoundaryVersion:  "something yet more",
			Name:             "some name",
			Description:      "some description",
			PublicAddr:       "some addr",
			OperationalState: "some state",
		},
	}
	for _, c := range connInfo {
		st, err := c.AsConnectionStateStruct()
		assert.NoError(t, err)

		got, err := GetWorkerInfoFromStateMap(context.Background(), &testConn{st: st})
		require.NoError(t, err)
		assert.Equal(t, c, got)
	}
}

func TestWorkerConnectionInfo_errors(t *testing.T) {
	t.Run("wrong connection type", func(t *testing.T) {
		c, _ := net.Pipe()
		got, err := GetWorkerInfoFromStateMap(context.Background(), c)
		assert.ErrorContains(t, err, "conn is not a state provider")
		assert.Nil(t, got)
	})
	t.Run("no state on connection", func(t *testing.T) {
		got, err := GetWorkerInfoFromStateMap(context.Background(), &testConn{})
		assert.ErrorContains(t, err, "no state attached")
		assert.Nil(t, got)
	})

	t.Run("wrong type in struct", func(t *testing.T) {
		st, err := structpb.NewStruct(map[string]interface{}{
			"worker_id": 1.2480,
		})
		require.NoError(t, err)
		require.NotNil(t, st)
		got, err := GetWorkerInfoFromStateMap(context.Background(), &testConn{st: st})
		assert.ErrorContains(t, err, "'worker_id' expected type 'string'")
		assert.Nil(t, got)
	})
}
