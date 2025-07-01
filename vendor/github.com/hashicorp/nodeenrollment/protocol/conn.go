// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package protocol

import (
	"crypto/tls"
	"fmt"

	"github.com/hashicorp/nodeenrollment"
	"google.golang.org/protobuf/types/known/structpb"
)

// Conn embeds a *tls.Conn and allows us to add extra bits into it
type Conn struct {
	*tls.Conn
	clientNextProtos []string
	clientState      *structpb.Struct
}

// NewConn constructs a conn from a base TLS connection and possibly client next
// protos.
//
// Supported options: WithExtraAlpnProtos (used to set clientNextProtos),
// WithState (storing client state information)
func NewConn(base *tls.Conn, opt ...nodeenrollment.Option) (*Conn, error) {
	const op = "nodeenrollment.protocol.NewConn"
	opts, err := nodeenrollment.GetOpts(opt...)
	if err != nil {
		return nil, fmt.Errorf("(%s) error parsing options: %w", op, err)
	}

	conn := &Conn{
		Conn:        base,
		clientState: opts.WithState,
	}
	switch {
	case opts.WithExtraAlpnProtos == nil:
	case len(opts.WithExtraAlpnProtos) == 0:
		conn.clientNextProtos = make([]string, 0)
	default:
		conn.clientNextProtos = make([]string, len(opts.WithExtraAlpnProtos))
		copy(conn.clientNextProtos, opts.WithExtraAlpnProtos)
	}
	return conn, nil
}

// ClientNextProtos returns the value of NextProtos originally presented by the
// client at connection time
func (c *Conn) ClientNextProtos() []string {
	switch {
	case c == nil:
		return nil
	case c.clientNextProtos == nil:
		return nil
	case len(c.clientNextProtos) == 0:
		return []string{}
	default:
		ret := make([]string, len(c.clientNextProtos))
		copy(ret, c.clientNextProtos)
		return ret
	}
}

// ClientState returns the value of the state embedded into the original client
// request, which may be nil
func (c *Conn) ClientState() *structpb.Struct {
	return c.clientState
}
