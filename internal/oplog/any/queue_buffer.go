package any

import (
	"fmt"
	"io"
)

// QueueBuffer will be used to buffer a queue
type QueueBuffer []byte

// Write prepends the contents of p to the buffer and satisfies io.Writer
func (b *QueueBuffer) Write(p []byte) (int, error) {
	// io.Writer shouldn't modify the buf it's handed (even temporarily)
	cp := make([]byte, len(p))
	if n := copy(cp, p); n != len(p) {
		return 0, fmt.Errorf("failed to make copy of provided buf")
	}
	(*b) = append(cp, (*b)...)
	return len(p), nil
}

// Read reads the next len(p) bytes from the buffer or until the buffer
// is empty.  It satisfies io.Reader
func (b *QueueBuffer) Read(p []byte) (int, error) {
	if x := len(*b) - len(p); x >= 0 {
		n := copy(p, (*b)[x:])
		*b = (*b)[:x]
		return n, nil
	}
	n := copy(p, *b)
	*b = nil
	return n, io.EOF
}

// Len returns the length of the buffer
func (b *QueueBuffer) Len() int {
	return len(*b)
}

// Next returns the next n bytes from the buffer
func (b *QueueBuffer) Next(n int) []byte {
	if x := len(*b) - n; x >= 0 {
		p := make([]byte, n)
		copy(p, (*b)[x:])
		*b = (*b)[:x]
		return p
	}
	p := *b
	*b = nil
	return p
}
