// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package bsr

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/internal/bsr/internal/fstest"
	"github.com/hashicorp/boundary/internal/bsr/kms"
	"github.com/hashicorp/boundary/internal/storage"
	"github.com/stretchr/testify/require"
)

func TestPopulateMeta(t *testing.T) {
	ctx := context.Background()

	keys, err := kms.CreateKeys(ctx, kms.TestWrapper(t), "session")
	require.NoError(t, err)

	sessionId := "session"
	sessionProtocol := "TEST"

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

func TestOpenBSRMethods(t *testing.T) {
	ctx := context.Background()

	keys, err := kms.CreateKeys(ctx, kms.TestWrapper(t), "session")
	require.NoError(t, err)

	f := &fstest.MemFS{}
	sessionId := "session"
	sessionMeta := TestSessionMeta(sessionId, Protocol("test"))

	sesh, err := NewSession(ctx, sessionMeta, f, keys, WithSupportsMultiplex(true))
	require.NoError(t, err)
	require.NotNil(t, sesh)

	connectionId := "connection"
	connMeta := &ConnectionMeta{Id: connectionId}
	conn, err := sesh.NewConnection(ctx, connMeta)
	require.NoError(t, err)
	require.NotNil(t, conn)

	channelId := "channel"
	chanMeta := &ChannelMeta{
		Id:   channelId,
		Type: "chan",
	}
	ch, err := conn.NewChannel(ctx, chanMeta)
	require.NoError(t, err)
	require.NotNil(t, ch)

	ch.Close(ctx)
	conn.Close(ctx)
	sesh.Close(ctx)

	keyFn := func(w kms.WrappedKeys) (kms.UnwrappedKeys, error) {
		u := kms.UnwrappedKeys{
			BsrKey:  keys.BsrKey,
			PrivKey: keys.PrivKey,
		}
		return u, nil
	}

	opSesh, err := OpenSession(ctx, sessionId, f, keyFn)
	require.NoError(t, err)
	require.NotNil(t, opSesh)
	sesh.Meta.connections = opSesh.Meta.connections
	require.Equal(t, sesh.Meta, opSesh.Meta)

	opConn, err := opSesh.OpenConnection(ctx, fmt.Sprintf("connection.%s", connectionId))
	require.NoError(t, err)
	require.NotNil(t, opConn)
	conn.Meta.channels = opConn.Meta.channels
	require.Equal(t, conn.Meta, opConn.Meta)

	opChan, err := opConn.OpenChannel(ctx, fmt.Sprintf("channel.%s", channelId))
	require.NoError(t, err)
	require.NotNil(t, opChan)
	require.Equal(t, ch.Meta, opChan.Meta)
}

func TestOpenSession(t *testing.T) {
	ctx := context.Background()

	keys, err := kms.CreateKeys(ctx, kms.TestWrapper(t), "session")
	require.NoError(t, err)

	keyFn := func(w kms.WrappedKeys) (kms.UnwrappedKeys, error) {
		u := kms.UnwrappedKeys{
			BsrKey:  keys.BsrKey,
			PrivKey: keys.PrivKey,
		}
		return u, nil
	}

	f := &fstest.MemFS{}
	sessionId := "session"

	cases := []struct {
		name            string
		id              string
		f               storage.FS
		keyFn           kms.KeyUnwrapCallbackFunc
		wantErr         bool
		wantErrContains string
	}{
		{
			name:            "no-session-id",
			f:               f,
			keyFn:           keyFn,
			wantErr:         true,
			wantErrContains: "bsr.OpenSession: missing session recording id: invalid parameter",
		},
		{
			name:            "no-key-fn",
			id:              sessionId,
			f:               f,
			wantErr:         true,
			wantErrContains: "bsr.OpenSession: missing key unwrap function: invalid parameter",
		},
		{
			name:            "no-storage",
			id:              sessionId,
			keyFn:           keyFn,
			wantErr:         true,
			wantErrContains: "bsr.OpenSession: missing storage: invalid parameter",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := OpenSession(ctx, tc.id, tc.f, tc.keyFn)
			if tc.wantErr {
				require.Error(t, err)
				require.ErrorContains(t, err, tc.wantErrContains)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, got)
		})
	}
}

func TestOpenConnection(t *testing.T) {
	ctx := context.Background()

	connMap := make(map[string]bool)
	connMap["connection"] = true
	meta := TestSessionMeta("sessionId", Protocol("test"))
	meta.connections = connMap

	cases := []struct {
		name            string
		id              string
		wantErr         bool
		wantErrContains string
	}{
		{
			name:            "no-conn-id",
			wantErr:         true,
			wantErrContains: "bsr.OpenConnection: missing connection id: invalid parameter",
		},

		{
			name:            "bad-conn-id",
			id:              "bogus",
			wantErr:         true,
			wantErrContains: "bsr.OpenConnection: connection id does not exist within this session: invalid parameter",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sesh := Session{
				Meta: meta,
			}
			got, err := sesh.OpenConnection(ctx, tc.id)
			if tc.wantErr {
				require.Error(t, err)
				require.ErrorContains(t, err, tc.wantErrContains)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, got)
		})
	}
}

func TestOpenChannel(t *testing.T) {
	ctx := context.Background()

	chanMap := make(map[string]bool)
	chanMap["channel"] = true

	cases := []struct {
		name            string
		id              string
		wantErr         bool
		wantErrContains string
	}{
		{
			name:            "no-chan-id",
			wantErr:         true,
			wantErrContains: "bsr.OpenChannel: missing channel id: invalid parameter",
		},

		{
			name:            "bad-chan-id",
			id:              "bogus",
			wantErr:         true,
			wantErrContains: "bsr.OpenChannel: channel id does not exist within this connection: invalid parameter",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conn := Connection{
				Meta: &ConnectionMeta{
					channels: chanMap,
				},
			}
			got, err := conn.OpenChannel(ctx, tc.id)
			if tc.wantErr {
				require.Error(t, err)
				require.ErrorContains(t, err, tc.wantErrContains)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, got)
		})
	}
}
