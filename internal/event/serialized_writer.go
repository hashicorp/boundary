// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package event

import (
	"bytes"
	"fmt"
	"io"
	"sync"
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
		return 0, fmt.Errorf("%s: missing serialized writer: %w", op, ErrInvalidParameter)
	}
	if s.l == nil {
		return 0, fmt.Errorf("%s: missing lock: %w", op, ErrInvalidParameter)
	}
	if s.w == nil {
		return 0, fmt.Errorf("%s: missing writer: %w", op, ErrInvalidParameter)
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
