// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package convert

import (
	"context"
	"fmt"
	"io"

	"github.com/hashicorp/boundary/internal/bsr"
	"github.com/hashicorp/boundary/internal/bsr/internal/is"
	"github.com/hashicorp/boundary/internal/bsr/ssh"
	"github.com/hashicorp/boundary/internal/storage"
)

// ToAsciicast accepts a bsr.Session and will convert the underlying BSR connection or channel file to an asciinema file.
// The tempFs will be used to write the asciinema file to disk
// It returns an io.Reader to the converted asciinema file.
// This supports the following options:
//   - WithChannelId to indicate this conversion should occur on a channel on a multiplexed session
//   - WithMinWidth to set a minimum width for the asciicast
//   - WithMinHeigh to set a minimum height for the asciicast
func ToAsciicast(ctx context.Context, session *bsr.Session, tmp storage.TempFile, connectionId string, options ...Option) (io.ReadCloser, error) {
	const op = "convert.ToAsciicast"

	switch {
	case is.Nil(session):
		return nil, fmt.Errorf("%s: missing session: %w", op, bsr.ErrInvalidParameter)
	case is.Nil(session.Meta):
		return nil, fmt.Errorf("%s: missing session meta: %w", op, bsr.ErrInvalidParameter)
	case is.Nil(tmp):
		return nil, fmt.Errorf("%s: missing temp file: %w", op, bsr.ErrInvalidParameter)
	case connectionId == "":
		return nil, fmt.Errorf("%s: missing connection id: %w", op, bsr.ErrInvalidParameter)
	}

	opts := getOpts(options...)

	switch session.Meta.Protocol {
	case ssh.Protocol:
		chanId := opts.withChannelId
		switch {
		case chanId == "":
			return nil, fmt.Errorf("%s: protocol %q requires channel id to convert: %w", op, ssh.Protocol, bsr.ErrInvalidParameter)
		}

		conn, err := session.OpenConnection(ctx, connectionId)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
		defer conn.Close(ctx)

		ch, err := conn.OpenChannel(ctx, chanId)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
		defer ch.Close(ctx)

		switch chs := ch.Summary.(type) {
		case *ssh.ChannelSummary:
			switch chs.SessionProgram {
			case ssh.Shell, ssh.Exec:
				reqScanner, err := ch.OpenRequestScanner(ctx, bsr.Inbound)
				if err != nil {
					if !is.Nil(reqScanner) {
						reqScanner.Close()
					}
					return nil, fmt.Errorf("%s: %w", op, err)
				}
				defer reqScanner.Close()

				msgScanner, err := ch.OpenMessageScanner(ctx, bsr.Outbound)
				if err != nil {
					if !is.Nil(msgScanner) {
						msgScanner.Close()
					}
					return nil, fmt.Errorf("%s: %w", op, err)
				}
				defer msgScanner.Close()
				return sshChannelToAsciicast(ctx, reqScanner, msgScanner, tmp, options...)
			case "":
				return nil, fmt.Errorf("%s: session program not set for asciicast conversion", op)
			default:
				return nil, fmt.Errorf("%s: unsupported %q session program for asciicast conversion", op, chs.SessionProgram)
			}
		default:
			return nil, fmt.Errorf("%s: unexpected error occurred with channel summary. possibly a malformed Boundary Session Recording", op)
		}

	default:
		return nil, fmt.Errorf("%s: %w", op, ErrUnsupportedProtocol)
	}
}
