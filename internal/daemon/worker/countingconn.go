package worker

import (
	"net"
	"sync"
)

type countingConn struct {
	net.Conn

	bytesRead    uint64
	bytesWritten uint64
	// Use mutex for counters as net.Conn methods may be called concurrently
	// https://github.com/golang/go/issues/27203#issuecomment-415854958
	mu sync.Mutex
}

// BytesRead reports the number of bytes read so far
func (c *countingConn) BytesRead() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.bytesRead
}

// BytesWritten reports the number of bytes written so far
func (c *countingConn) BytesWritten() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.bytesWritten
}

// Read wraps the embedded conn's Read and counts the number of bytes read.
func (c *countingConn) Read(in []byte) (int, error) {
	n, err := c.Conn.Read(in)
	c.mu.Lock()
	c.bytesRead += uint64(n)
	c.mu.Unlock()
	return n, err
}

// Write wraps the embedded conn's Write and counts the number of bytes read.
func (c *countingConn) Write(in []byte) (int, error) {
	n, err := c.Conn.Write(in)
	c.mu.Lock()
	c.bytesWritten += uint64(n)
	c.mu.Unlock()
	return n, err
}
