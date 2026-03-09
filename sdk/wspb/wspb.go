// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

// Package wspb provides convenience functions for reading and writing protobuf
// messages via a websocket.
package wspb

import (
	"bytes"
	"context"
	"fmt"
	"sync"

	"github.com/coder/websocket"
	"google.golang.org/protobuf/proto"
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
	t, r, err := c.Reader(ctx)
	if err != nil {
		return err
	}

	if t != websocket.MessageBinary {
		return fmt.Errorf("expected binary message for protobuf but got %q", t.String())
	}

	b := getBuffer()
	defer putBuffer(b)

	if _, err := b.ReadFrom(r); err != nil {
		return fmt.Errorf("error reading from reader: %w", err)
	}

	if err := proto.Unmarshal(b.Bytes(), m); err != nil {
		c.Close(websocket.StatusInvalidFramePayloadData, "failed to unmarshal protobuf")
		return fmt.Errorf("failed to unmarshal protobuf: %w", err)
	}

	return nil
}

// Write writes protobuf message m to websocket c.
func Write(ctx context.Context, c *websocket.Conn, m proto.Message) error {
	const op = "wspb.Write"

	bytes, err := proto.Marshal(m)
	if err != nil {
		return fmt.Errorf("failed to marshal protobuf: %w", err)
	}

	return c.Write(ctx, websocket.MessageBinary, bytes)
}
