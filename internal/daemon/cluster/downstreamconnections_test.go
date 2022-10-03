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
	assert.Empty(t, dm.Connected())

	t.Run("single connection", func(t *testing.T) {
		w1, g1 := net.Pipe()
		dm.addConnection("1", w1)
		assert.Equal(t, []string{"1"}, dm.Connected())

		dm.Disconnect("1")
		assert.ErrorIs(t, w1.SetReadDeadline(time.Now()), io.ErrClosedPipe)
		assert.ErrorIs(t, g1.SetReadDeadline(time.Now()), io.ErrClosedPipe)

		assert.Empty(t, dm.Connected())
	})

	t.Run("multiple connection with single name", func(t *testing.T) {
		w1, g1 := net.Pipe()
		dm.addConnection("1", w1)
		assert.Equal(t, []string{"1"}, dm.Connected())
		w2, g2 := net.Pipe()
		dm.addConnection("1", w2)
		assert.Equal(t, []string{"1"}, dm.Connected())

		assert.NoError(t, w1.SetReadDeadline(time.Now()))
		assert.NoError(t, g1.SetReadDeadline(time.Now()))
		assert.NoError(t, w2.SetReadDeadline(time.Now()))
		assert.NoError(t, g2.SetReadDeadline(time.Now()))

		dm.Disconnect("1")
		assert.ErrorIs(t, w1.SetReadDeadline(time.Now()), io.ErrClosedPipe)
		assert.ErrorIs(t, g1.SetReadDeadline(time.Now()), io.ErrClosedPipe)
		assert.ErrorIs(t, w2.SetReadDeadline(time.Now()), io.ErrClosedPipe)
		assert.ErrorIs(t, g2.SetReadDeadline(time.Now()), io.ErrClosedPipe)

		assert.Empty(t, dm.Connected())
	})

	t.Run("multiple connection with different names", func(t *testing.T) {
		w1, g1 := net.Pipe()
		dm.addConnection("1", w1)
		assert.Equal(t, []string{"1"}, dm.Connected())
		w2, g2 := net.Pipe()
		dm.addConnection("2", w2)
		got := dm.Connected()
		sort.Strings(got)
		assert.Equal(t, []string{"1", "2"}, got)

		dm.Disconnect("1")
		assert.ErrorIs(t, w1.SetReadDeadline(time.Now()), io.ErrClosedPipe)
		assert.ErrorIs(t, g1.SetReadDeadline(time.Now()), io.ErrClosedPipe)

		assert.NoError(t, w2.SetReadDeadline(time.Now()))
		assert.NoError(t, g2.SetReadDeadline(time.Now()))

		assert.Equal(t, []string{"2"}, dm.Connected())

		dm.Disconnect("2")
		assert.ErrorIs(t, w2.SetReadDeadline(time.Now()), io.ErrClosedPipe)
		assert.ErrorIs(t, g2.SetReadDeadline(time.Now()), io.ErrClosedPipe)
	})
}

func TestDisconnectUnauthorized(t *testing.T) {
	dm := NewDownstreamManager()
	w1, _ := net.Pipe()
	dm.addConnection("w1", w1)
	w2a, _ := net.Pipe()
	dm.addConnection("w2", w2a)
	w2b, _ := net.Pipe()
	dm.addConnection("w2", w2b)
	w3, _ := net.Pipe()
	dm.addConnection("w3", w3)

	assert.NoError(t, w1.SetReadDeadline(time.Now()))
	assert.NoError(t, w2a.SetReadDeadline(time.Now()))
	assert.NoError(t, w2b.SetReadDeadline(time.Now()))
	assert.NoError(t, w3.SetReadDeadline(time.Now()))

	DisconnectUnauthorized(dm, dm.Connected(), []string{"w3"})
	assert.ErrorIs(t, w1.SetReadDeadline(time.Now()), io.ErrClosedPipe)
	assert.ErrorIs(t, w2a.SetReadDeadline(time.Now()), io.ErrClosedPipe)
	assert.ErrorIs(t, w2b.SetReadDeadline(time.Now()), io.ErrClosedPipe)
	assert.NoError(t, w3.SetReadDeadline(time.Now()))
}
