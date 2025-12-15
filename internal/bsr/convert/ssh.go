// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package convert

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/hashicorp/boundary/internal/bsr"
	"github.com/hashicorp/boundary/internal/bsr/convert/internal/asciicast"
	"github.com/hashicorp/boundary/internal/bsr/internal/is"
	"github.com/hashicorp/boundary/internal/bsr/ssh"
)

// sshChannelToAsciicast will convert a recording of an ssh channel from a BSR
// into an asciicast. This expects two bsr.ChunkScanners. One for the recording
// of ssh requests and one for the recording of messages. In order to generate
// a useful asciicast, it should be the inbound requests and outbound messages.
// This also expects a io.ReadWriteSeeker that will be used to write the
// asciicast.  This is then reset and returned as a io.ReadCloser. The caller
// should call Close on the returned io.ReadCloser after reading the asciicast.
func sshChannelToAsciicast(ctx context.Context, requestScanner *bsr.ChunkScanner, messagesScanner *bsr.ChunkScanner, w io.ReadWriteSeeker, options ...Option) (io.ReadCloser, error) {
	const op = "convert.sshChannelToAsciicast"

	switch {
	case is.Nil(requestScanner):
		return nil, fmt.Errorf("%s: missing request scanner: %w", op, bsr.ErrInvalidParameter)
	case is.Nil(messagesScanner):
		return nil, fmt.Errorf("%s: missing message scanner: %w", op, bsr.ErrInvalidParameter)
	case is.Nil(w):
		return nil, fmt.Errorf("%s: missing read write seeker: %w", op, bsr.ErrInvalidParameter)
	}

	opts := getOpts(options...)

	header := asciicast.NewHeader()

	if opts.withMinWidth > 0 {
		header.Width = opts.withMinWidth
	}
	if opts.withMinHeight > 0 {
		header.Height = opts.withMinHeight
	}

	// Walk the requests to extract any information for asciicast header.  This
	// will come from either a Pty and/or Env request. There could also be
	// additional WindowChange requests to resize the terminal.  In picking an
	// initial height/width for the asciicast, this will pick the largest heigh
	// and width seen between a Pty and any WindowChange requests
	//
	// There may not be either request, so the header defaults to some sane values.
	// We would expect at most one Pty request per channel. Although this is
	// not required by and RFC. If there happen to be multiple, it is probably
	// ok to just use the last one.
	if err := bsr.ChunkWalk(ctx, requestScanner, func(ctx context.Context, c bsr.Chunk) error {
		switch c.GetProtocol() {
		case ssh.Protocol:
			switch c.GetType() {
			case ssh.PtyReqChunkType:
				cc := c.(*ssh.PtyRequest)

				if cc.GetTerminalWidthCharacters() > opts.withMinWidth {
					header.Width = cc.GetTerminalWidthCharacters()
				}
				if cc.GetTerminalHeightRows() > opts.withMinHeight {
					header.Height = cc.GetTerminalHeightRows()
				}
				if cc.GetTermEnvVar() != "" {
					header.Env.Term = cc.GetTermEnvVar()
				}
			case ssh.WindowChangeReqChunkType:
				cc := c.(*ssh.WindowChangeRequest)

				if cc.GetTerminalWidthColumns() > header.Width {
					header.Width = cc.GetTerminalWidthColumns()
				}
				if cc.GetTerminalHeightRows() > header.Height {
					header.Height = cc.GetTerminalHeightRows()
				}

			case ssh.EnvReqChunkType:
				cc := c.(*ssh.EnvRequest)
				if cc.GetVariableName() == "SHELL" && cc.GetVariableValue() != "" {
					header.Env.Shell = cc.GetVariableValue()
				}
			}
			return nil
		default:
			return ErrUnsupportedProtocol
		}
	}); err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	// Now walk the message chunks. The ChunkHeader should contain the last bit
	// of information needed to complete the asciicast header; the start timestamp.
	// After that it should just be creating asciicast.Event for each DataChunk.
	enc := json.NewEncoder(w)
	var wroteHeader bool
	if err := bsr.ChunkWalk(ctx, messagesScanner, func(ctx context.Context, c bsr.Chunk) error {
		switch c.GetProtocol() {
		case ssh.Protocol:
			switch c.GetType() {
			case bsr.ChunkHeader:
				cc := c.(*bsr.HeaderChunk)
				if wroteHeader {
					return fmt.Errorf("multiple header chunks: %w", ErrMalformedBsr)
				}
				header.Timestamp = asciicast.Time(cc.GetTimestamp().AsTime())
				if err := enc.Encode(&header); err != nil {
					return err
				}
				wroteHeader = true
			case ssh.DataChunkType:
				if !wroteHeader {
					return fmt.Errorf("data chunk before header: %w", ErrMalformedBsr)
				}
				cc := c.(*ssh.DataChunk)
				tt := cc.GetTimestamp().AsTime()
				ts := float64(tt.Sub(time.Time(header.Timestamp))) / float64(time.Second)
				data := cc.Data

				e, err := asciicast.NewEvent(asciicast.Output, ts, data)
				if err != nil {
					return err
				}

				if err := enc.Encode(e); err != nil {
					return err
				}
			}
			return nil
		default:
			return ErrUnsupportedProtocol
		}
	}); err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	if _, err := w.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}

	var r io.ReadCloser
	if v, ok := w.(io.ReadCloser); ok {
		r = v
	} else {
		r = io.NopCloser(w)
	}
	return r, nil
}
