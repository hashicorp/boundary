// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

// Package journal provides a writer that uses a journal file to aide in recovery.
package journal

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"

	"github.com/hashicorp/boundary/internal/bsr/internal/is"
)

var errInvalidParameter = errors.New("invalid parameter")

type writerFile interface {
	fs.File
	io.WriteCloser
	io.StringWriter
	WriteAndClose([]byte) (int, error)
}

// Journal is used to record meta data about the operations that will be and
// have been performed on bsr containers and files. This can be used to aide in
// recovery if a system crashes while writing a bsr.
type Journal struct {
	io.Writer
}

// New creates a Journal that is written to the provided io.Writer.
func New(_ context.Context, w io.Writer) (*Journal, error) {
	const op = "journal.New"

	switch {
	case is.Nil(w):
		return nil, fmt.Errorf("%s: missing writer: %w", op, errInvalidParameter)
	}
	return &Journal{
		Writer: w,
	}, nil
}

// Close optionally closes the underlying io.Writer if it also implements
// io.Closer.
func (j *Journal) Close() error {
	var i interface{} = j.Writer
	v, ok := i.(io.WriteCloser)
	if ok {
		if err := v.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Record writes the entry to the journal.
func (j *Journal) Record(op, f string) error {
	_, err := j.Write([]byte(fmt.Sprintf("%s %s\n", op, f)))
	return err
}

// File is a writable file that will update a Journal as it closed.
type File struct {
	j *Journal
	writerFile
}

// NewFile wraps the provided writable file in a journaled File. When the file
// is closed, the journal will be written to.
func NewFile(_ context.Context, f writerFile, j *Journal) (*File, error) {
	const op = "journal.NewFile"
	switch {
	case is.Nil(f):
		return nil, fmt.Errorf("%s: missing writable file: %w", op, errInvalidParameter)
	case is.Nil(j):
		return nil, fmt.Errorf("%s: missing journal: %w", op, errInvalidParameter)
	}

	return &File{
		j:          j,
		writerFile: f,
	}, nil
}

// Close closes the underlying file, writing to the journal prior to and after
// closing.
func (f *File) Close() error {
	const op = "journal.(File).Close"

	s, err := f.Stat()
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	if err := f.j.Record("CLOSING", s.Name()); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	if err := f.writerFile.Close(); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	return f.j.Record("CLOSED", s.Name())
}

// WriteAndClose writes to the underlying file and closes the underlying file,
// writing to the journal prior to and after
func (f *File) WriteAndClose(b []byte) (int, error) {
	const op = "journal.(File).Close"

	s, err := f.Stat()
	if err != nil {
		return 0, fmt.Errorf("%s: %w", op, err)
	}

	if err := f.j.Record("CLOSING", s.Name()); err != nil {
		return 0, fmt.Errorf("%s: %w", op, err)
	}

	n, err := f.writerFile.WriteAndClose(b)
	if err != nil {
		return n, fmt.Errorf("%s: %w", op, err)
	}

	if err := f.j.Record("CLOSED", s.Name()); err != nil {
		return n, fmt.Errorf("%s: %w", op, err)
	}

	return n, err
}

var _ writerFile = (*File)(nil)
