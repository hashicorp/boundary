package wsconn

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"go.uber.org/atomic"
	"nhooyr.io/websocket"
)

type command byte

const (
	bin     command = 0x00
	stopped command = 0x01
)

type CCNetConn struct {
	n        net.Conn
	wroteEof *atomic.Bool
	readEof  *atomic.Bool
	eofMutex sync.RWMutex

	// Note: we do not mutex this buffer as we expect that although two separate
	// goroutines might call read/write concurrently, only one goroutine
	// actually calls read
	readBuf bytes.Buffer

	// Stores the amount of data outstanding in the current frame
	currFrameOutstanding int
}

func NewCCNetConn(ctx context.Context, conn *websocket.Conn) *CCNetConn {
	return &CCNetConn{
		n:        websocket.NetConn(ctx, conn, websocket.MessageBinary),
		wroteEof: atomic.NewBool(false),
		readEof:  atomic.NewBool(false),
	}
}

func (c *CCNetConn) Read(b []byte) (int, error) {
	c.eofMutex.RLock()
	defer c.eofMutex.RUnlock()

	// We're EOF
	if c.readEof.Load() {
		return 0, io.EOF
	}

	// Start with the header; we may have partially read it already
	var sizeToRead int = 9 - c.readBuf.Len()
	// If we're in the middle of a frame, adjust to the amount of data
	// outstanding minus the amount we have, so we read no more than the rest of
	// the frame.
	if c.currFrameOutstanding > 0 {
		sizeToRead = c.currFrameOutstanding - c.readBuf.Len()
	}

	buf := make([]byte, sizeToRead)
	_, readErr := c.n.Read(buf)
	switch readErr {
	case io.EOF:
		// Store this so we don't try to read anymore past this final handling of data
		c.readEof.Store(true)
	case nil:
	default:
		return 0, readErr
	}

	_, _ = c.readBuf.Write(buf)

	// If we haven't read anything, don't try to do anything more with data,
	// just exit
	if c.readBuf.Len() == 0 {
		if c.readEof.Load() {
			return 0, io.EOF
		}
		return 0, nil
	}

	switch {
	case c.currFrameOutstanding == 0:
		// It's a beautiful baby frame!
		if c.readBuf.Len() < 9 {
			// Leave it in the buffer, we don't even have enough to read the
			// size yet
			return 0, nil
		}

		switch command(c.readBuf.Next(1)[0]) {
		case bin:
		case stopped:
			// Ensure we do no more reads as the other side has promised it will
			// deliver no more wrapped data
			c.readEof.Store(true)
			return 0, io.EOF
		}

		c.currFrameOutstanding = int(binary.BigEndian.Uint64(c.readBuf.Next(8)))
		return 0, nil

	case c.currFrameOutstanding > 0:
		// At this point, err will never be set since we know there is data in
		// the buffer from the check. We have to make sure we don't read into
		// the next frame.
		var maxReadLen int
		switch {
		case c.currFrameOutstanding <= c.readBuf.Len():
			// Read only the amount of the current frame
			maxReadLen = c.currFrameOutstanding

		case c.currFrameOutstanding > c.readBuf.Len():
			// Read only up to the end of the current buffer
			maxReadLen = c.readBuf.Len()
		}
		// Finally cap by the length of the passed-in buffer itself
		if len(b) < maxReadLen {
			maxReadLen = len(b)
		}
		numDrained, _ := c.readBuf.Read(b[0:maxReadLen])
		c.currFrameOutstanding -= numDrained
		return numDrained, nil

	case c.currFrameOutstanding < 0:
		return 0, errors.New("outstanding frame negative")
	}

	return 0, errors.New("unreachable buffer condition")
}

func (c *CCNetConn) Write(b []byte) (int, error) {
	c.eofMutex.Lock()
	defer c.eofMutex.Unlock()

	if c.wroteEof.Load() {
		return 0, io.EOF
	}

	// Build a frame (I know, I know, it's TLV, but ya know, frame rolls off the
	// tongue better) that can carry a command, expected length, and data
	frame := make([]byte, len(b)+9)
	frame[0] = byte(bin)
	binary.BigEndian.PutUint64(frame[1:9], uint64(len(b)))
	copy(frame[9:], b)

	written, err := c.n.Write(frame)
	if err != nil {
		if written == 0 {
			return written, err
		}
	}

	return written - 9, err
}

func (c *CCNetConn) Close() error {
	c.eofMutex.Lock()
	defer c.eofMutex.Unlock()

	frame := make([]byte, 9)
	frame[0] = byte(stopped)
	_, err := c.n.Write(frame)
	if err != nil {
		return err
	}
	c.wroteEof.Store(true)
	return nil
}

func (c *CCNetConn) LocalAddr() net.Addr {
	return c.n.LocalAddr()
}

func (c *CCNetConn) RemoteAddr() net.Addr {
	return c.n.RemoteAddr()
}

func (c *CCNetConn) SetDeadline(t time.Time) error {
	return c.n.SetDeadline(t)
}

func (c *CCNetConn) SetReadDeadline(t time.Time) error {
	return c.n.SetReadDeadline(t)
}

func (c *CCNetConn) SetWriteDeadline(t time.Time) error {
	return c.n.SetWriteDeadline(t)
}
