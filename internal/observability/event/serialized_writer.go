package event

import (
	"bytes"
	"io"
	"sync"

	"github.com/hashicorp/boundary/internal/errors"
)

// serializedWriter uses a mutext to serializes all writes to its io.Writer
type serializedWriter struct {
	l *sync.Mutex
	w io.Writer
}

// Write uses a mutex to serialize all writes
func (s *serializedWriter) Write(p []byte) (int, error) {
	const op = "event.(serializedWriter).Write"
	if s == nil {
		return 0, errors.New(errors.InvalidParameter, op, "missing serialized writer")
	}
	if s.l == nil {
		return 0, errors.New(errors.InvalidParameter, op, "missing lock")
	}
	if s.w == nil {
		return 0, errors.New(errors.InvalidParameter, op, "missing writer")
	}

	s.l.Lock()
	defer s.l.Unlock()
	reader := bytes.NewReader(p)

	n, err := reader.WriteTo(s.w)
	if err != nil {
		return 0, err
	}
	return int(n), err
}
