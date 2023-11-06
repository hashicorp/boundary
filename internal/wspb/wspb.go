// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

// Package wspb provides convenience functions for reading and writing protobuf
// messages via a websocket.
package wspb

import (
	"bytes"
	"context"
	"fmt"
	"sync"

	"github.com/hashicorp/boundary/internal/errors"
	"google.golang.org/protobuf/proto"
	"nhooyr.io/websocket"
)

var pool sync.Pool

func getBuffer() *bytes.Buffer {
	b := pool.Get()
	if b == nil {
		return &bytes.Buffer{}
	}
	return b.(*bytes.Buffer)
}

func putBuffer(b *bytes.Buffer) {
	b.Reset()
	pool.Put(b)
}

// Read reads from websocket c into protobuf message m.
func Read(ctx context.Context, c *websocket.Conn, m proto.Message) error {
	const op = "wspb.Read"

	t, r, err := c.Reader(ctx)
	if err != nil {
		return err
	}

	if t != websocket.MessageBinary {
		return errors.New(ctx, errors.Internal, op, "", errors.WithMsg("expected binary message for protobuf but got: %v", t))
	}

	b := getBuffer()
	defer putBuffer(b)

	if _, err := b.ReadFrom(r); err != nil {
		return errors.Wrap(ctx, err, op)
	}

	if err := proto.Unmarshal(b.Bytes(), m); err != nil {
		c.Close(websocket.StatusInvalidFramePayloadData, "failed to unmarshal protobuf")
		return errors.Wrap(ctx, fmt.Errorf("failed to unmarshal protobuf: %w", err), op)
	}

	return nil
}

// Write writes protobuf message m to websocket c.
func Write(ctx context.Context, c *websocket.Conn, m proto.Message) error {
	const op = "wspb.Write"

	bytes, err := proto.Marshal(m)
	if err != nil {
		return errors.Wrap(ctx, fmt.Errorf("failed to marshal protobuf: %w", err), op)
	}

	return c.Write(ctx, websocket.MessageBinary, bytes)
}
