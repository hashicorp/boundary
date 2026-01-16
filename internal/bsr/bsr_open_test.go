// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package bsr

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/internal/bsr/internal/fstest"
	"github.com/hashicorp/boundary/internal/bsr/kms"
	"github.com/hashicorp/boundary/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	protocol := TestRegisterSummaryAllocFunc(t)

	keys, err := kms.CreateKeys(ctx, kms.TestWrapper(t), "session")
	require.NoError(t, err)

	f := &fstest.MemFS{}
	sessionId := "s_01234567890"
	srm := &SessionRecordingMeta{
		Id:       "sr_012344567890",
		Protocol: protocol,
	}
	sessionMeta := TestSessionMeta(sessionId)

	sesh, err := NewSession(ctx, srm, sessionMeta, f, keys, WithSupportsMultiplex(true))
	require.NoError(t, err)
	require.NotNil(t, sesh)

	require.NoError(t, sesh.EncodeSummary(ctx, &BaseChannelSummary{
		Id:                    "TEST_CHANNEL_ID",
		ConnectionRecordingId: "TEST_CONNECTION_RECORDING_ID",
	}))

	connectionId := "connection"
	connMeta := &ConnectionRecordingMeta{Id: connectionId}
	conn, err := sesh.NewConnection(ctx, connMeta)
	require.NoError(t, err)
	require.NotNil(t, conn)

	require.NoError(t, conn.EncodeSummary(ctx, &BaseConnectionSummary{
		Id:           "TEST_CONNECTION_ID",
		ChannelCount: 1,
	}))

	channelId := "channel"
	chanMeta := &ChannelRecordingMeta{
		Id:   channelId,
		Type: "chan",
	}
	ch, err := conn.NewChannel(ctx, chanMeta)
	require.NoError(t, err)
	require.NotNil(t, ch)

	require.NoError(t, ch.EncodeSummary(ctx, &BaseSessionSummary{
		Id:              "TEST_SESSION_ID",
		ConnectionCount: 1,
	}))

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

func TestOpenBSRMethods_WithoutSummaryAllocFunc(t *testing.T) {
	ctx := context.Background()
	f := &fstest.MemFS{}

	cases := []struct {
		name                string
		protocol            Protocol
		sId                 int
		sessionAllocFunc    SessionSummary
		connectionAllocFunc ConnectionSummary
		channelAllocFunc    ChannelSummary
		expectedError       string
		wantSessionErr      bool
		wantConnErr         bool
		wantChanErr         bool
	}{
		{
			name:                "without-session-allocFunc",
			protocol:            Protocol("TEST_BSR_OPEN_SESSION_PROTOCOL"),
			sId:                 12345,
			sessionAllocFunc:    nil,
			connectionAllocFunc: &BaseConnectionSummary{Id: "TEST_CONNECTION_ID", ChannelCount: 1},
			channelAllocFunc:    &BaseChannelSummary{Id: "TEST_CHANNEL_ID", ConnectionRecordingId: "TEST_CONNECTION_RECORDING_ID"},
			expectedError:       "bsr.OpenSession: failed to get summary type",
			wantSessionErr:      true,
		},
		{
			name:                "without-connection-allocFunc",
			protocol:            Protocol("TEST_BSR_OPEN_CONNECTION_PROTOCOL"),
			sId:                 45678,
			sessionAllocFunc:    &BaseSessionSummary{Id: "TEST_SESSION_ID", ConnectionCount: 1},
			connectionAllocFunc: nil,
			channelAllocFunc:    &BaseChannelSummary{Id: "TEST_CHANNEL_ID", ConnectionRecordingId: "TEST_CONNECTION_RECORDING_ID"},
			expectedError:       "bsr.(Session).OpenConnection: failed to get summary type",
			wantConnErr:         true,
		},
		{
			name:                "without-channel-allocFunc",
			protocol:            Protocol("TEST_BSR_OPEN_CHANNEL_PROTOCOL"),
			sId:                 23588,
			sessionAllocFunc:    &BaseSessionSummary{Id: "TEST_SESSION_ID", ConnectionCount: 1},
			connectionAllocFunc: &BaseConnectionSummary{Id: "TEST_CONNECTION_ID", ChannelCount: 1},
			expectedError:       "bsr.OpenChannel: failed to get summary type",
			wantChanErr:         true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.sessionAllocFunc != nil {
				err := RegisterSummaryAllocFunc(tc.protocol, SessionContainer, func(ctx context.Context) Summary {
					return tc.sessionAllocFunc
				})
				require.NoError(t, err)
			}
			if tc.connectionAllocFunc != nil {
				err := RegisterSummaryAllocFunc(tc.protocol, ConnectionContainer, func(ctx context.Context) Summary {
					return tc.connectionAllocFunc
				})
				require.NoError(t, err)
			}
			if tc.channelAllocFunc != nil {
				err := RegisterSummaryAllocFunc(tc.protocol, ChannelContainer, func(ctx context.Context) Summary {
					return tc.channelAllocFunc
				})
				require.NoError(t, err)
			}

			keys, err := kms.CreateKeys(ctx, kms.TestWrapper(t), "session")
			require.NoError(t, err)

			sessionId := fmt.Sprintf("s_%v", tc.sId)
			srm := &SessionRecordingMeta{
				Id:       fmt.Sprintf("sr_%v", tc.sId),
				Protocol: tc.protocol,
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

			require.NoError(t, sesh.EncodeSummary(ctx, tc.sessionAllocFunc))
			require.NoError(t, conn.EncodeSummary(ctx, tc.connectionAllocFunc))
			require.NoError(t, ch.EncodeSummary(ctx, tc.channelAllocFunc))

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
			if tc.wantSessionErr {
				require.Error(t, err)
				require.ErrorContains(t, err, tc.expectedError)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, opSesh)

			opConn, err := opSesh.OpenConnection(ctx, connectionId)
			if tc.wantConnErr {
				require.Error(t, err)
				require.ErrorContains(t, err, tc.expectedError)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, opConn)

			opChan, err := opConn.OpenChannel(ctx, channelId)
			if tc.wantChanErr {
				require.Error(t, err)
				require.ErrorContains(t, err, tc.expectedError)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, opChan)
		})
	}
}

func TestCloseBSRMethods(t *testing.T) {
	ctx := context.Background()

	protocol := TestRegisterSummaryAllocFunc(t)
	sessionRecordingId := "sr_012344567890"
	sessionId := "s_012344567890"
	connectionId := "connection"
	channelId := "channel"

	keys, err := kms.CreateKeys(ctx, kms.TestWrapper(t), "session")
	require.NoError(t, err)

	f := fstest.NewMemFS(fstest.WithOriginalFile())

	srm := &SessionRecordingMeta{
		Id:       sessionRecordingId,
		Protocol: protocol,
	}
	sessionMeta := TestSessionMeta(sessionId)

	sesh, err := NewSession(ctx, srm, sessionMeta, f, keys, WithSupportsMultiplex(true))
	require.NoError(t, err)
	require.NotNil(t, sesh)

	require.NoError(t, sesh.EncodeSummary(ctx, &BaseChannelSummary{
		Id:                    "TEST_CHANNEL_ID",
		ConnectionRecordingId: "TEST_CONNECTION_RECORDING_ID",
	}))

	connMeta := &ConnectionRecordingMeta{Id: connectionId}
	conn, err := sesh.NewConnection(ctx, connMeta)
	require.NoError(t, err)
	require.NotNil(t, conn)

	require.NoError(t, conn.EncodeSummary(ctx, &BaseConnectionSummary{
		Id:           "TEST_CONNECTION_ID",
		ChannelCount: 1,
	}))

	chanMeta := &ChannelRecordingMeta{
		Id:   channelId,
		Type: "chan",
	}
	ch, err := conn.NewChannel(ctx, chanMeta)
	require.NoError(t, err)
	require.NotNil(t, ch)

	require.NoError(t, ch.EncodeSummary(ctx, &BaseSessionSummary{
		Id:              "TEST_SESSION_ID",
		ConnectionCount: 1,
	}))

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
	assert.True(t, sessionContainer.IsClosed())

	// Ensure all session files are closed
	for _, file := range sessionContainer.Files {
		assert.True(t, file.Closed)
	}

	// Get connection container
	connectionContainer := sessionContainer.Sub[fmt.Sprintf(connectionFileNameTemplate, connectionId)]
	require.NotNil(t, connectionContainer)
	assert.True(t, connectionContainer.IsClosed())

	// Ensure all connection files are closed
	for _, file := range connectionContainer.Files {
		assert.True(t, file.Closed)
	}

	// Get channel container
	channelContainer := connectionContainer.Sub[fmt.Sprintf(channelFileNameTemplate, channelId)]
	require.NotNil(t, channelContainer)
	assert.True(t, channelContainer.IsClosed())

	// Ensure all channel files are closed
	for _, file := range channelContainer.Files {
		assert.True(t, file.Closed)
	}
}
