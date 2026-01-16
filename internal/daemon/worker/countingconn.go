// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package worker

import (
	"net"
	"sync"
)

// countingConn is a `net.Conn` implementation that records the bytes that go
// across Read() and Write(). All other `net.Conn` function calls are a
// pass-through to the underlying `net.Conn`, meaning it's also safe to call
// those functions directly on the underlying object, if you have access to it.
type countingConn struct {
	net.Conn

	bytesRead    int64
	bytesWritten int64
	// Use mutex for counters as net.Conn methods may be called concurrently
	// https://github.com/golang/go/issues/27203#issuecomment-415854958
	mu sync.Mutex
}

// BytesRead reports the number of bytes read so far
func (c *countingConn) BytesRead() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.bytesRead
}

// BytesWritten reports the number of bytes written so far
func (c *countingConn) BytesWritten() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.bytesWritten
}

// Read wraps the embedded conn's Read() and counts the number of bytes read
// (the number of bytes the client sent to us).
func (c *countingConn) Read(in []byte) (int, error) {
	n, err := c.Conn.Read(in)
	c.mu.Lock()
	c.bytesRead += int64(n)
	c.mu.Unlock()
	return n, err
}

// Write wraps the embedded conn's Write() and counts the number of bytes
// written (the number of bytes we sent to the client).
func (c *countingConn) Write(in []byte) (int, error) {
	n, err := c.Conn.Write(in)
	c.mu.Lock()
	c.bytesWritten += int64(n)
	c.mu.Unlock()
	return n, err
}
