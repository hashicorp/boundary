// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package bsr

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strings"
)

// SessionRecordingMeta contains metadata about a session in a BSR.
// Most fields are written to the meta file as k:v pairs
// Slice fields are written to the meta file as id_k:v
// Nested slice fields are written as parentId_parentKey_id_k:v
type SessionRecordingMeta struct {
	Id          string
	Protocol    Protocol
	connections map[string]bool
}

func (s *SessionRecordingMeta) writeMeta(ctx context.Context, c *container) error {
	_, err := c.WriteMeta(ctx, "id", s.Id)
	if err != nil {
		return err
	}
	_, err = c.WriteMeta(ctx, "protocol", string(s.Protocol))
	if err != nil {
		return err
	}
	return nil
}

// decodeSessionRecordingMeta will populate a SessionRecordingMeta for an opened BSR Session
func decodeSessionRecordingMeta(ctx context.Context, r io.Reader) (*SessionRecordingMeta, error) {
	const op = "bsr.decodeSessionRecordingMeta"

	switch {
	case r == nil:
		return nil, fmt.Errorf("%s: missing session meta file: %w", op, ErrInvalidParameter)
	}

	connections := make(map[string]bool)
	s := &SessionRecordingMeta{}
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		l := scanner.Text()
		if len(l) == 0 {
			continue
		}
		k, v, ok := strings.Cut(l, ":")
		if !ok {
			return nil, fmt.Errorf("%s: session meta file contains invalid entry; expecting k: v pair:%s", op, l)
		}
		v = strings.TrimSpace(v)
		switch {
		case k == "id":
			s.Id = v
		case k == "protocol":
			s.Protocol = Protocol(v)

		// connections
		case k == "connection":
			connections[v] = true
		}
	}

	s.connections = connections

	return s, nil
}

// ConnectionRecordingMeta contains metadata about a connection in a BSR.
type ConnectionRecordingMeta struct {
	Id       string
	channels map[string]bool
}

func (c ConnectionRecordingMeta) isValid() bool {
	switch {
	case c.Id == "":
		return false
	default:
		return true
	}
}

// decodeConnectionRecordingMeta will populate the ConnectionRecordingMeta for a BSR Connection
func decodeConnectionRecordingMeta(ctx context.Context, r io.Reader) (*ConnectionRecordingMeta, error) {
	const op = "bsr.decodeConnectionRecordingMeta"

	switch {
	case r == nil:
		return nil, fmt.Errorf("%s: missing connection meta file: %w", op, ErrInvalidParameter)
	}
	c := &ConnectionRecordingMeta{}
	channels := make(map[string]bool)
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		l := scanner.Text()
		if len(l) == 0 {
			continue
		}
		k, v, ok := strings.Cut(l, ":")
		if !ok {
			return nil, fmt.Errorf("%s: connection meta file contains invalid entry; expecting k: v pair:%s", op, l)
		}
		v = strings.TrimSpace(v)
		switch {
		case k == "id":
			c.Id = v
		case k == "channel":
			channels[v] = true
		}
	}
	c.channels = channels

	return c, nil
}

// ChannelRecordingMeta contains metadata about a channel in a BSR.
type ChannelRecordingMeta struct {
	Id   string
	Type string
}

func (c ChannelRecordingMeta) isValid() bool {
	switch {
	case c.Id == "":
		return false
	case c.Type == "":
		return false
	default:
		return true
	}
}

// decodeChannelRecordingMeta will populate the ChannelRecordingMeta for a BSR Channel
func decodeChannelRecordingMeta(ctx context.Context, r io.Reader) (*ChannelRecordingMeta, error) {
	const op = "bsr.decodeChannelRecordingMeta"

	switch {
	case r == nil:
		return nil, fmt.Errorf("%s: missing channel meta file: %w", op, ErrInvalidParameter)
	}

	c := &ChannelRecordingMeta{}
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		l := scanner.Text()
		if len(l) == 0 {
			continue
		}
		k, v, ok := strings.Cut(l, ":")
		if !ok {
			return nil, fmt.Errorf("%s: channel meta file contains invalid entry; expecting k: v pair:%s", op, l)
		}
		v = strings.TrimSpace(v)
		switch {
		case k == "id":
			c.Id = v
		case k == "channelType":
			c.Type = v
		}
	}

	return c, nil
}
