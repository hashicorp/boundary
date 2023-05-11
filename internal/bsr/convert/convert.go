// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

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
// It returns an io.Reader to the converted asciinema file
// Supports WithChannelId() to indicate this conversion should occur on a channel on a multiplexed session
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

		ch, err := conn.OpenChannel(ctx, chanId)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}

		// TODO sanity checks before getting the data files:
		// - check connection summary to see if there was an exec or shell request

		reqScanner, err := ch.OpenRequestScanner(ctx, bsr.Inbound)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}

		msgScanner, err := ch.OpenMessageScanner(ctx, bsr.Outbound)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}

		return sshChannelToAsciicast(ctx, reqScanner, msgScanner, tmp)
	default:
		return nil, fmt.Errorf("%s: %w", op, ErrUnsupportedProtocol)
	}
}
