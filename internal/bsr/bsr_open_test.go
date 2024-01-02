// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1


package bsr

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/internal/bsr/internal/fstest"
	"github.com/hashicorp/boundary/internal/bsr/kms"
	"github.com/hashicorp/boundary/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/square/go-jose.v2/json"
)

func TestPopulateMeta(t *testing.T) {
	ctx := context.Background()

	keys, err := kms.CreateKeys(ctx, kms.TestWrapper(t), "session")
	require.NoError(t, err)

	sessionId := "s_01234567890"
	srm := &SessionRecordingMeta{
		Id:       "sr_012344567890",
		Protocol: Protocol("TEST"),
	}

	// Populate session meta
	sessionMeta := TestSessionMeta(sessionId)
	s, err := NewSession(ctx, srm, sessionMeta, &fstest.MemFS{}, keys, WithSupportsMultiplex(true))
	require.NoError(t, err)
	require.NotNil(t, s)

	// Reset meta and populate it from the meta file
	s.Meta = &SessionRecordingMeta{}
	sm, err := decodeSessionRecordingMeta(ctx, s.container.meta)
	require.NoError(t, err)
	s.Meta = sm
	require.Equal(t, s.Meta.Id, srm.Id)
	require.Equal(t, s.Meta.Protocol, srm.Protocol)

	gotSessionMeta := &SessionMeta{}
	r, err := s.container.container.OpenFile(ctx, sessionMetaFileName)
	require.NoError(t, err)
	dec := json.NewDecoder(r)
	err = dec.Decode(gotSessionMeta)
	require.NoError(t, err)
	assert.Equal(t, sessionMeta, gotSessionMeta)

	// Populate connection meta
	connectionId := "connection"
	c, err := s.NewConnection(ctx, &ConnectionRecordingMeta{Id: connectionId})
	require.NoError(t, err)
	require.NotNil(t, c)

	c.Meta = &ConnectionRecordingMeta{}
	cm, err := decodeConnectionRecordingMeta(ctx, c.container.meta)
	require.NoError(t, err)
	c.Meta = cm
	require.Equal(t, c.Meta.Id, connectionId)

	// Populate channel meta
	channelId := "channel"
	channelType := "mythical"
	ch, err := c.NewChannel(ctx, &ChannelRecordingMeta{Id: channelId, Type: channelType})
	require.NoError(t, err)
	require.NotNil(t, ch)

	ch.Meta = &ChannelRecordingMeta{}
	chM, err := decodeChannelRecordingMeta(ctx, ch.container.meta)
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
	sessionId := "s_01234567890"
	srm := &SessionRecordingMeta{
		Id:       "sr_012344567890",
		Protocol: Protocol("TEST"),
	}
	sessionMeta := TestSessionMeta(sessionId)

	sesh, err := NewSession(ctx, srm, sessionMeta, f, keys, WithSupportsMultiplex(true))
	require.NoError(t, err)
	require.NotNil(t, sesh)

	connectionId := "connection"
	connMeta := &ConnectionRecordingMeta{Id: connectionId}
	conn, err := sesh.NewConnection(ctx, connMeta)
	require.NoError(t, err)
	require.NotNil(t, conn)

	channelId := "channel"
	chanMeta := &ChannelRecordingMeta{
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

	opSesh, err := OpenSession(ctx, srm.Id, f, keyFn)
	require.NoError(t, err)
	require.NotNil(t, opSesh)
	sesh.Meta.connections = opSesh.Meta.connections
	require.Equal(t, sesh.Meta, opSesh.Meta)

	opConn, err := opSesh.OpenConnection(ctx, connectionId)
	require.NoError(t, err)
	require.NotNil(t, opConn)
	conn.Meta.channels = opConn.Meta.channels
	require.Equal(t, conn.Meta, opConn.Meta)

	opChan, err := opConn.OpenChannel(ctx, channelId)
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
	sessionId := "s_01234567890"
	srm := &SessionRecordingMeta{
		Id:          "sr_012344567890",
		Protocol:    Protocol("TEST"),
		connections: connMap,
	}
	meta := TestSessionMeta(sessionId)

	cases := []struct {
		name            string
		id              string
		wantErr         bool
		wantErrContains string
	}{
		{
			name:            "no-conn-id",
			wantErr:         true,
			wantErrContains: "bsr.(Session).OpenConnection: missing connection id: invalid parameter",
		},

		{
			name:            "bad-conn-id",
			id:              "bogus",
			wantErr:         true,
			wantErrContains: "bsr.(Session).OpenConnection: connection id does not exist within this session: invalid parameter",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sesh := Session{
				Meta:        srm,
				SessionMeta: meta,
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
				Meta: &ConnectionRecordingMeta{
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

func TestCloseBSRMethods(t *testing.T) {
	ctx := context.Background()

	protocol := Protocol("TEST_CLOSED_FILE")
	sessionRecordingId := "sr_012344567890"
	sessionId := "s_012344567890"
	connectionId := "connection"
	channelId := "channel"

	keys, err := kms.CreateKeys(ctx, kms.TestWrapper(t), "session")
	require.NoError(t, err)

	require.NoError(t, err)

	f := &fstest.MemFS{}
	srm := &SessionRecordingMeta{
		Id:       sessionRecordingId,
		Protocol: protocol,
	}
	sessionMeta := TestSessionMeta(sessionId)

	sesh, err := NewSession(ctx, srm, sessionMeta, f, keys, WithSupportsMultiplex(true))
	require.NoError(t, err)
	require.NotNil(t, sesh)

	connMeta := &ConnectionRecordingMeta{Id: connectionId}
	conn, err := sesh.NewConnection(ctx, connMeta)
	require.NoError(t, err)
	require.NotNil(t, conn)

	chanMeta := &ChannelRecordingMeta{
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

	opSesh, err := OpenSession(ctx, srm.Id, f, keyFn)
	require.NoError(t, err)
	require.NotNil(t, opSesh)

	opConn, err := opSesh.OpenConnection(ctx, connectionId)
	require.NoError(t, err)
	require.NotNil(t, opConn)

	opChan, err := opConn.OpenChannel(ctx, channelId)
	require.NoError(t, err)
	require.NotNil(t, opChan)

	// Close all opened containers
	require.NoError(t, opChan.Close(ctx))
	require.NoError(t, opConn.Close(ctx))
	require.NoError(t, opSesh.Close(ctx))

	// Get session container
	sessionContainer := f.Containers[fmt.Sprintf(bsrFileNameTemplate, sessionRecordingId)]
	require.NotNil(t, sessionContainer)
	assert.True(t, sessionContainer.Closed)

	// Ensure all session files are closed
	for _, file := range sessionContainer.Files {
		assert.True(t, file.Closed)
	}

	// Get connection container
	connectionContainer := sessionContainer.Sub[fmt.Sprintf(connectionFileNameTemplate, connectionId)]
	require.NotNil(t, connectionContainer)
	assert.True(t, connectionContainer.Closed)

	// Ensure all connection files are closed
	for _, file := range connectionContainer.Files {
		assert.True(t, file.Closed)
	}

	// Get channel container
	channelContainer := connectionContainer.Sub[fmt.Sprintf(channelFileNameTemplate, channelId)]
	require.NotNil(t, channelContainer)
	assert.True(t, channelContainer.Closed)

	// Ensure all channel files are closed
	for _, file := range channelContainer.Files {
		assert.True(t, file.Closed)
	}
}
