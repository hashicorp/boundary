// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package bsr

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/bsr/internal/fstest"
	"github.com/hashicorp/boundary/internal/bsr/kms"
	"github.com/stretchr/testify/require"
)

func TestPopulateMeta(t *testing.T) {
	ctx := context.Background()

	keys, err := kms.CreateKeys(ctx, kms.TestWrapper(t), "session")
	require.NoError(t, err)

	sessionId := "session"
	sessionProtocol := "SSH"

	// Populate session meta
	sessionMeta := TestSessionMeta(sessionId, Protocol((sessionProtocol)))
	s, err := NewSession(ctx, sessionMeta, &fstest.MemFS{}, keys, WithSupportsMultiplex(true))
	require.NoError(t, err)
	require.NotNil(t, s)

	// Reset meta and populate it from the meta file
	s.Meta = &SessionMeta{}
	sm, err := decodeSessionMeta(ctx, s.container.meta)
	require.NoError(t, err)
	s.Meta = sm
	require.Equal(t, s.Meta.Id, sessionId)
	require.Equal(t, s.Meta.Protocol.ToText(), sessionProtocol)
	require.Equal(t, s.Meta.Target, sessionMeta.Target)
	require.Equal(t, s.Meta.User, sessionMeta.User)
	require.Equal(t, s.Meta.StaticHost, sessionMeta.StaticHost)

	// Populate connection meta
	connectionId := "connection"
	c, err := s.NewConnection(ctx, &ConnectionMeta{Id: connectionId})
	require.NoError(t, err)
	require.NotNil(t, c)

	c.Meta = &ConnectionMeta{}
	cm, err := decodeConnectionMeta(ctx, c.container.meta)
	require.NoError(t, err)
	c.Meta = cm
	require.Equal(t, c.Meta.Id, connectionId)

	// Populate channel meta
	channelId := "channel"
	channelType := "mythical"
	ch, err := c.NewChannel(ctx, &ChannelMeta{Id: channelId, Type: channelType})
	require.NoError(t, err)
	require.NotNil(t, ch)

	ch.Meta = &ChannelMeta{}
	chM, err := decodeChannelMeta(ctx, ch.container.meta)
	require.NoError(t, err)
	ch.Meta = chM
	require.Equal(t, ch.Meta.Id, channelId)
	require.Equal(t, ch.Meta.Type, channelType)
}
