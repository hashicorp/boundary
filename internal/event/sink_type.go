// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package event

import (
	"fmt"
)

const (
	StderrSink SinkType = "stderr" // StderrSink is written to stderr
	FileSink   SinkType = "file"   // FileSink is written to a file
	WriterSink SinkType = "writer" // WriterSink is written to an io.Writer
)

type SinkType string // SinkType defines the type of sink in a config stanza (file, stderr, writer)

func (t SinkType) Validate() error {
	const op = "event.(SinkType).validate"
	switch t {
	case StderrSink, FileSink, WriterSink:
		return nil
	default:
		return fmt.Errorf("%s: '%s' is not a valid sink type: %w", op, t, ErrInvalidParameter)
	}
}
