// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package cluster

import (
	"io"
	"net"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNewDownstreamManager(t *testing.T) {
	dm := NewDownstreamManager()
	assert.Empty(t, dm.Connected().UnmappedKeyIds())
	assert.Empty(t, dm.Connected().WorkerIds())

	t.Run("single connection", func(t *testing.T) {
		w1, g1 := net.Pipe()
		dm.addConnection("1", w1)
		st := dm.Connected()
		assert.Equal(t, []string{"1"}, st.UnmappedKeyIds())
		assert.Equal(t, []string{"1"}, st.AllKeyIds())

		dm.disconnectKeys("1")
		assert.ErrorIs(t, w1.SetReadDeadline(time.Now()), io.ErrClosedPipe)
		assert.ErrorIs(t, g1.SetReadDeadline(time.Now()), io.ErrClosedPipe)

		assert.Empty(t, dm.Connected().UnmappedKeyIds())
		assert.Empty(t, dm.Connected().AllKeyIds())
	})

	t.Run("single connection with worker", func(t *testing.T) {
		w1, g1 := net.Pipe()
		dm.addConnection("1", w1)
		dm.mapKeyToWorkerId("1", "w1")

		st := dm.Connected()
		assert.Empty(t, st.UnmappedKeyIds())
		assert.Equal(t, []string{"1"}, st.AllKeyIds())
		assert.Equal(t, []string{"w1"}, st.WorkerIds())

		dm.disconnectWorkerId("w1")
		assert.ErrorIs(t, w1.SetReadDeadline(time.Now()), io.ErrClosedPipe)
		assert.ErrorIs(t, g1.SetReadDeadline(time.Now()), io.ErrClosedPipe)

		assert.Empty(t, dm.Connected().UnmappedKeyIds())
		assert.Empty(t, dm.Connected().AllKeyIds())
		assert.Empty(t, dm.Connected().WorkerIds())
	})

	t.Run("multiple connection with single name", func(t *testing.T) {
		w1, g1 := net.Pipe()
		dm.addConnection("1", w1)
		assert.Equal(t, []string{"1"}, dm.Connected().UnmappedKeyIds())
		w2, g2 := net.Pipe()
		dm.addConnection("1", w2)
		assert.Equal(t, []string{"1"}, dm.Connected().UnmappedKeyIds())
		assert.Equal(t, []string{"1"}, dm.Connected().AllKeyIds())

		assert.NoError(t, w1.SetReadDeadline(time.Now()))
		assert.NoError(t, g1.SetReadDeadline(time.Now()))
		assert.NoError(t, w2.SetReadDeadline(time.Now()))
		assert.NoError(t, g2.SetReadDeadline(time.Now()))

		dm.disconnectKeys("1")
		assert.ErrorIs(t, w1.SetReadDeadline(time.Now()), io.ErrClosedPipe)
		assert.ErrorIs(t, g1.SetReadDeadline(time.Now()), io.ErrClosedPipe)
		assert.ErrorIs(t, w2.SetReadDeadline(time.Now()), io.ErrClosedPipe)
		assert.ErrorIs(t, g2.SetReadDeadline(time.Now()), io.ErrClosedPipe)

		assert.Empty(t, dm.Connected().UnmappedKeyIds())
		assert.Empty(t, dm.Connected().AllKeyIds())
	})

	t.Run("multiple connection with single key mapped to worker", func(t *testing.T) {
		w1, g1 := net.Pipe()
		dm.addConnection("1", w1)
		assert.Equal(t, []string{"1"}, dm.Connected().UnmappedKeyIds())
		w2, g2 := net.Pipe()
		dm.addConnection("1", w2)
		assert.Equal(t, []string{"1"}, dm.Connected().UnmappedKeyIds())

		dm.mapKeyToWorkerId("1", "w1")
		assert.Equal(t, []string{"w1"}, dm.Connected().WorkerIds())
		assert.Empty(t, dm.Connected().UnmappedKeyIds())
		assert.Equal(t, []string{"1"}, dm.Connected().AllKeyIds())

		assert.NoError(t, w1.SetReadDeadline(time.Now()))
		assert.NoError(t, g1.SetReadDeadline(time.Now()))
		assert.NoError(t, w2.SetReadDeadline(time.Now()))
		assert.NoError(t, g2.SetReadDeadline(time.Now()))

		dm.disconnectWorkerId("w1")
		assert.ErrorIs(t, w1.SetReadDeadline(time.Now()), io.ErrClosedPipe)
		assert.ErrorIs(t, g1.SetReadDeadline(time.Now()), io.ErrClosedPipe)
		assert.ErrorIs(t, w2.SetReadDeadline(time.Now()), io.ErrClosedPipe)
		assert.ErrorIs(t, g2.SetReadDeadline(time.Now()), io.ErrClosedPipe)

		assert.Empty(t, dm.Connected().UnmappedKeyIds())
		assert.Empty(t, dm.Connected().WorkerIds())
		assert.Empty(t, dm.Connected().AllKeyIds())
	})

	t.Run("multiple connection with different keys", func(t *testing.T) {
		w1, g1 := net.Pipe()
		dm.addConnection("1", w1)
		assert.Equal(t, []string{"1"}, dm.Connected().UnmappedKeyIds())
		w2, g2 := net.Pipe()
		dm.addConnection("2", w2)
		got := dm.Connected().UnmappedKeyIds()
		sort.Strings(got)
		assert.ElementsMatch(t, []string{"1", "2"}, got)
		assert.ElementsMatch(t, []string{"1", "2"}, dm.Connected().AllKeyIds())

		dm.disconnectKeys("1")
		assert.ErrorIs(t, w1.SetReadDeadline(time.Now()), io.ErrClosedPipe)
		assert.ErrorIs(t, g1.SetReadDeadline(time.Now()), io.ErrClosedPipe)

		assert.NoError(t, w2.SetReadDeadline(time.Now()))
		assert.NoError(t, g2.SetReadDeadline(time.Now()))

		assert.Equal(t, []string{"2"}, dm.Connected().UnmappedKeyIds())

		dm.disconnectKeys("2")
		assert.ErrorIs(t, w2.SetReadDeadline(time.Now()), io.ErrClosedPipe)
		assert.ErrorIs(t, g2.SetReadDeadline(time.Now()), io.ErrClosedPipe)
		assert.Empty(t, dm.Connected().UnmappedKeyIds())
		assert.Empty(t, dm.Connected().WorkerIds())
	})

	t.Run("multiple connection with different keys to same worker", func(t *testing.T) {
		w1, g1 := net.Pipe()
		dm.addConnection("1", w1)
		assert.Equal(t, []string{"1"}, dm.Connected().UnmappedKeyIds())
		w2, g2 := net.Pipe()
		dm.addConnection("2", w2)
		assert.ElementsMatch(t, []string{"1", "2"}, dm.Connected().UnmappedKeyIds())

		dm.mapKeyToWorkerId("1", "w1")
		dm.mapKeyToWorkerId("2", "w1")
		assert.Equal(t, []string{"w1"}, dm.Connected().WorkerIds())
		assert.Empty(t, dm.Connected().UnmappedKeyIds())
		assert.ElementsMatch(t, []string{"1", "2"}, dm.Connected().AllKeyIds())

		assert.NoError(t, w1.SetReadDeadline(time.Now()))
		assert.NoError(t, g1.SetReadDeadline(time.Now()))
		assert.NoError(t, w2.SetReadDeadline(time.Now()))
		assert.NoError(t, g2.SetReadDeadline(time.Now()))

		dm.disconnectWorkerId("w1")
		assert.ErrorIs(t, w1.SetReadDeadline(time.Now()), io.ErrClosedPipe)
		assert.ErrorIs(t, g1.SetReadDeadline(time.Now()), io.ErrClosedPipe)
		assert.ErrorIs(t, w2.SetReadDeadline(time.Now()), io.ErrClosedPipe)
		assert.ErrorIs(t, g2.SetReadDeadline(time.Now()), io.ErrClosedPipe)
		assert.Empty(t, dm.Connected().UnmappedKeyIds())
		assert.Empty(t, dm.Connected().WorkerIds())
	})

	t.Run("multiple connection with different key to partial worker", func(t *testing.T) {
		w1, g1 := net.Pipe()
		dm.addConnection("1", w1)
		assert.Equal(t, []string{"1"}, dm.Connected().UnmappedKeyIds())
		w2, g2 := net.Pipe()
		dm.addConnection("2", w2)
		assert.ElementsMatch(t, []string{"1", "2"}, dm.Connected().UnmappedKeyIds())

		dm.mapKeyToWorkerId("1", "w1")
		assert.Equal(t, []string{"w1"}, dm.Connected().WorkerIds())
		assert.Equal(t, []string{"2"}, dm.Connected().UnmappedKeyIds())

		assert.NoError(t, w1.SetReadDeadline(time.Now()))
		assert.NoError(t, g1.SetReadDeadline(time.Now()))
		assert.NoError(t, w2.SetReadDeadline(time.Now()))
		assert.NoError(t, g2.SetReadDeadline(time.Now()))

		dm.disconnectWorkerId("w1")
		assert.ErrorIs(t, w1.SetReadDeadline(time.Now()), io.ErrClosedPipe)
		assert.ErrorIs(t, g1.SetReadDeadline(time.Now()), io.ErrClosedPipe)
		assert.NoError(t, w2.SetReadDeadline(time.Now()))
		assert.NoError(t, g2.SetReadDeadline(time.Now()))
		dm.disconnectKeys("2")
		assert.ErrorIs(t, w2.SetReadDeadline(time.Now()), io.ErrClosedPipe)
		assert.ErrorIs(t, g2.SetReadDeadline(time.Now()), io.ErrClosedPipe)
		assert.Empty(t, dm.Connected().UnmappedKeyIds())
		assert.Empty(t, dm.Connected().WorkerIds())
	})

	t.Run("multiple connection with different key to different workers", func(t *testing.T) {
		w1, g1 := net.Pipe()
		dm.addConnection("1", w1)
		assert.Equal(t, []string{"1"}, dm.Connected().UnmappedKeyIds())
		w2, g2 := net.Pipe()
		dm.addConnection("2", w2)
		assert.ElementsMatch(t, []string{"1", "2"}, dm.Connected().UnmappedKeyIds())

		dm.mapKeyToWorkerId("1", "w1")
		dm.mapKeyToWorkerId("2", "w2")
		assert.ElementsMatch(t, []string{"w1", "w2"}, dm.Connected().WorkerIds())
		assert.Empty(t, dm.Connected().UnmappedKeyIds())

		assert.NoError(t, w1.SetReadDeadline(time.Now()))
		assert.NoError(t, g1.SetReadDeadline(time.Now()))
		assert.NoError(t, w2.SetReadDeadline(time.Now()))
		assert.NoError(t, g2.SetReadDeadline(time.Now()))

		dm.disconnectWorkerId("w1")
		assert.ErrorIs(t, w1.SetReadDeadline(time.Now()), io.ErrClosedPipe)
		assert.ErrorIs(t, g1.SetReadDeadline(time.Now()), io.ErrClosedPipe)
		assert.NoError(t, w2.SetReadDeadline(time.Now()))
		assert.NoError(t, g2.SetReadDeadline(time.Now()))
		dm.disconnectWorkerId("w2")
		assert.ErrorIs(t, w2.SetReadDeadline(time.Now()), io.ErrClosedPipe)
		assert.ErrorIs(t, g2.SetReadDeadline(time.Now()), io.ErrClosedPipe)
		assert.Empty(t, dm.Connected().UnmappedKeyIds())
		assert.Empty(t, dm.Connected().WorkerIds())
	})
}

func TestConnectionState_Disconnect(t *testing.T) {
	t.Run("disconnect some key ids", func(t *testing.T) {
		dm := NewDownstreamManager()
		w1, _ := net.Pipe()
		dm.addConnection("1", w1)
		w2a, _ := net.Pipe()
		dm.addConnection("2", w2a)
		w2b, _ := net.Pipe()
		dm.addConnection("2", w2b)
		w3, _ := net.Pipe()
		dm.addConnection("3", w3)

		assert.NoError(t, w1.SetReadDeadline(time.Now()))
		assert.NoError(t, w2a.SetReadDeadline(time.Now()))
		assert.NoError(t, w2b.SetReadDeadline(time.Now()))
		assert.NoError(t, w3.SetReadDeadline(time.Now()))

		st := dm.Connected()
		assert.ElementsMatch(t, []string{"1", "2", "3"}, st.UnmappedKeyIds())

		st.DisconnectMissingUnmappedKeyIds([]string{"3"})
		assert.ErrorIs(t, w1.SetReadDeadline(time.Now()), io.ErrClosedPipe)
		assert.ErrorIs(t, w2a.SetReadDeadline(time.Now()), io.ErrClosedPipe)
		assert.ErrorIs(t, w2b.SetReadDeadline(time.Now()), io.ErrClosedPipe)
		assert.NoError(t, w3.SetReadDeadline(time.Now()))
	})

	t.Run("disconnect some key ids using DisconnectAll", func(t *testing.T) {
		dm := NewDownstreamManager()
		w1, _ := net.Pipe()
		dm.addConnection("1", w1)
		w2a, _ := net.Pipe()
		dm.addConnection("2", w2a)
		w2b, _ := net.Pipe()
		dm.addConnection("2", w2b)
		w3, _ := net.Pipe()
		dm.addConnection("3", w3)

		assert.NoError(t, w1.SetReadDeadline(time.Now()))
		assert.NoError(t, w2a.SetReadDeadline(time.Now()))
		assert.NoError(t, w2b.SetReadDeadline(time.Now()))
		assert.NoError(t, w3.SetReadDeadline(time.Now()))

		st := dm.Connected()
		assert.ElementsMatch(t, []string{"1", "2", "3"}, st.UnmappedKeyIds())

		st.DisconnectAllMissingKeyIds([]string{"3"})
		assert.ErrorIs(t, w1.SetReadDeadline(time.Now()), io.ErrClosedPipe)
		assert.ErrorIs(t, w2a.SetReadDeadline(time.Now()), io.ErrClosedPipe)
		assert.ErrorIs(t, w2b.SetReadDeadline(time.Now()), io.ErrClosedPipe)
		assert.NoError(t, w3.SetReadDeadline(time.Now()))
	})

	t.Run("disconnect all key ids", func(t *testing.T) {
		dm := NewDownstreamManager()
		w1, _ := net.Pipe()
		dm.addConnection("1", w1)
		w2a, _ := net.Pipe()
		dm.addConnection("2", w2a)
		w2b, _ := net.Pipe()
		dm.addConnection("2", w2b)
		w3, _ := net.Pipe()
		dm.addConnection("3", w3)

		assert.NoError(t, w1.SetReadDeadline(time.Now()))
		assert.NoError(t, w2a.SetReadDeadline(time.Now()))
		assert.NoError(t, w2b.SetReadDeadline(time.Now()))
		assert.NoError(t, w3.SetReadDeadline(time.Now()))

		st := dm.Connected()
		assert.ElementsMatch(t, []string{"1", "2", "3"}, st.UnmappedKeyIds())

		st.DisconnectMissingUnmappedKeyIds(nil)
		assert.ErrorIs(t, w1.SetReadDeadline(time.Now()), io.ErrClosedPipe)
		assert.ErrorIs(t, w2a.SetReadDeadline(time.Now()), io.ErrClosedPipe)
		assert.ErrorIs(t, w2b.SetReadDeadline(time.Now()), io.ErrClosedPipe)
		assert.ErrorIs(t, w3.SetReadDeadline(time.Now()), io.ErrClosedPipe)
	})

	t.Run("disconnect 1 worker id leave unmapped key id alone", func(t *testing.T) {
		dm := NewDownstreamManager()
		w1, _ := net.Pipe()
		dm.addConnection("1", w1)
		w2a, _ := net.Pipe()
		dm.addConnection("2", w2a)
		w2b, _ := net.Pipe()
		dm.addConnection("2", w2b)
		w3, _ := net.Pipe()
		dm.addConnection("3", w3)

		assert.NoError(t, w1.SetReadDeadline(time.Now()))
		assert.NoError(t, w2a.SetReadDeadline(time.Now()))
		assert.NoError(t, w2b.SetReadDeadline(time.Now()))
		assert.NoError(t, w3.SetReadDeadline(time.Now()))

		dm.mapKeyToWorkerId("1", "w1")
		dm.mapKeyToWorkerId("2", "w1")
		st := dm.Connected()
		assert.ElementsMatch(t, []string{"3"}, st.UnmappedKeyIds())
		assert.ElementsMatch(t, []string{"w1"}, st.WorkerIds())

		st.DisconnectMissingWorkers(nil)
		assert.ErrorIs(t, w1.SetReadDeadline(time.Now()), io.ErrClosedPipe)
		assert.ErrorIs(t, w2a.SetReadDeadline(time.Now()), io.ErrClosedPipe)
		assert.ErrorIs(t, w2b.SetReadDeadline(time.Now()), io.ErrClosedPipe)
		assert.NoError(t, w3.SetReadDeadline(time.Now()))
	})

	t.Run("disconnect 2 key ids using DisconnectAll overlapping with workers", func(t *testing.T) {
		dm := NewDownstreamManager()
		w1, _ := net.Pipe()
		dm.addConnection("1", w1)
		w2a, _ := net.Pipe()
		dm.addConnection("2", w2a)
		w2b, _ := net.Pipe()
		dm.addConnection("2", w2b)
		w3, _ := net.Pipe()
		dm.addConnection("3", w3)

		assert.NoError(t, w1.SetReadDeadline(time.Now()))
		assert.NoError(t, w2a.SetReadDeadline(time.Now()))
		assert.NoError(t, w2b.SetReadDeadline(time.Now()))
		assert.NoError(t, w3.SetReadDeadline(time.Now()))

		dm.mapKeyToWorkerId("1", "w1")
		dm.mapKeyToWorkerId("2", "w1")
		st := dm.Connected()
		assert.ElementsMatch(t, []string{"3"}, st.UnmappedKeyIds())
		assert.ElementsMatch(t, []string{"1", "2", "3"}, st.AllKeyIds())
		assert.ElementsMatch(t, []string{"w1"}, st.WorkerIds())

		st.DisconnectAllMissingKeyIds([]string{"1"})
		assert.NoError(t, w1.SetReadDeadline(time.Now()))
		assert.ErrorIs(t, w2a.SetReadDeadline(time.Now()), io.ErrClosedPipe)
		assert.ErrorIs(t, w2b.SetReadDeadline(time.Now()), io.ErrClosedPipe)
		assert.ErrorIs(t, w3.SetReadDeadline(time.Now()), io.ErrClosedPipe)
	})

	t.Run("disconnect 1 key id leave worker id alone", func(t *testing.T) {
		dm := NewDownstreamManager()
		w1, _ := net.Pipe()
		dm.addConnection("1", w1)
		w2a, _ := net.Pipe()
		dm.addConnection("2", w2a)
		w2b, _ := net.Pipe()
		dm.addConnection("2", w2b)
		w3, _ := net.Pipe()
		dm.addConnection("3", w3)

		assert.NoError(t, w1.SetReadDeadline(time.Now()))
		assert.NoError(t, w2a.SetReadDeadline(time.Now()))
		assert.NoError(t, w2b.SetReadDeadline(time.Now()))
		assert.NoError(t, w3.SetReadDeadline(time.Now()))

		dm.mapKeyToWorkerId("1", "w1")
		dm.mapKeyToWorkerId("2", "w1")
		st := dm.Connected()
		assert.ElementsMatch(t, []string{"3"}, st.UnmappedKeyIds())
		assert.ElementsMatch(t, []string{"w1"}, st.WorkerIds())

		st.DisconnectMissingUnmappedKeyIds(nil)
		assert.NoError(t, w1.SetReadDeadline(time.Now()))
		assert.NoError(t, w2a.SetReadDeadline(time.Now()))
		assert.NoError(t, w2b.SetReadDeadline(time.Now()))
		assert.ErrorIs(t, w3.SetReadDeadline(time.Now()), io.ErrClosedPipe)
	})

	t.Run("disconnect 1 worker id prividing a different worker", func(t *testing.T) {
		dm := NewDownstreamManager()
		w1, _ := net.Pipe()
		dm.addConnection("1", w1)
		w2a, _ := net.Pipe()
		dm.addConnection("2", w2a)
		w2b, _ := net.Pipe()
		dm.addConnection("2", w2b)
		w3, _ := net.Pipe()
		dm.addConnection("3", w3)

		assert.NoError(t, w1.SetReadDeadline(time.Now()))
		assert.NoError(t, w2a.SetReadDeadline(time.Now()))
		assert.NoError(t, w2b.SetReadDeadline(time.Now()))
		assert.NoError(t, w3.SetReadDeadline(time.Now()))

		dm.mapKeyToWorkerId("1", "w1")
		dm.mapKeyToWorkerId("2", "w1")
		dm.mapKeyToWorkerId("3", "w2")
		st := dm.Connected()
		assert.Empty(t, st.UnmappedKeyIds())
		assert.ElementsMatch(t, []string{"w1", "w2"}, st.WorkerIds())

		st.DisconnectMissingWorkers([]string{"w2"})
		assert.ErrorIs(t, w1.SetReadDeadline(time.Now()), io.ErrClosedPipe)
		assert.ErrorIs(t, w2a.SetReadDeadline(time.Now()), io.ErrClosedPipe)
		assert.ErrorIs(t, w2b.SetReadDeadline(time.Now()), io.ErrClosedPipe)
		assert.NoError(t, w3.SetReadDeadline(time.Now()))
	})
}
