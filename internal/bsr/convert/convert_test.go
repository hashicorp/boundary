// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package convert_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/bsr"
	"github.com/hashicorp/boundary/internal/bsr/convert"
	"github.com/hashicorp/boundary/internal/bsr/internal/fstest"
	"github.com/hashicorp/boundary/internal/bsr/kms"
	"github.com/hashicorp/boundary/internal/bsr/ssh"
	"github.com/hashicorp/boundary/internal/storage"
	"github.com/stretchr/testify/require"
)

func testChunks(s string, d bsr.Direction, p bsr.Protocol) []bsr.Chunk {
	ts := time.Date(2023, time.March, 16, 10, 47, 3, 14, time.UTC)

	return []bsr.Chunk{
		&bsr.HeaderChunk{
			BaseChunk: &bsr.BaseChunk{
				Protocol:  p,
				Direction: d,
				Timestamp: bsr.NewTimestamp(ts),
				Type:      bsr.ChunkHeader,
			},
			Compression: bsr.NoCompression,
			Encryption:  bsr.NoEncryption,
			SessionId:   s,
		},
		&bsr.EndChunk{
			BaseChunk: &bsr.BaseChunk{
				Protocol:  p,
				Direction: d,
				Timestamp: bsr.NewTimestamp(ts.Add(time.Second)),
				Type:      bsr.ChunkEnd,
			},
		},
	}
}

func writeToChannels(ctx context.Context, w storage.Writer, chunks ...bsr.Chunk) error {
	_, err := w.Write(bsr.Magic.Bytes())
	if err != nil {
		return err
	}
	enc, err := bsr.NewChunkEncoder(ctx, w, bsr.NoCompression, bsr.NoEncryption)
	if err != nil {
		return err
	}

	for _, c := range chunks {
		_, err := enc.Encode(ctx, c)
		if err != nil {
			return err
		}
	}

	return nil
}

func TestConvert_ToAsciicast_SessionProgram(t *testing.T) {
	ctx := context.Background()

	fs := &fstest.MemFS{}
	tmpfile, err := fstest.NewTempFile(t.Name())
	require.NoError(t, err)

	connectionId := "test_connection"
	channelId := "test_channel"

	cases := []struct {
		name     string
		chs      bsr.ChannelSummary
		protocol bsr.Protocol
		id       string
		wantErr  error
	}{
		{
			name:     "exec",
			id:       "01234567890",
			protocol: ssh.Protocol,
			chs: &ssh.ChannelSummary{
				ChannelSummary: &bsr.BaseChannelSummary{
					Id:                    channelId,
					ConnectionRecordingId: connectionId,
				},
				SessionProgram: ssh.Exec,
			},
			wantErr: nil,
		},
		{
			name:     "shell",
			id:       "11234567890",
			protocol: ssh.Protocol,
			chs: &ssh.ChannelSummary{
				ChannelSummary: &bsr.BaseChannelSummary{
					Id:                    channelId,
					ConnectionRecordingId: connectionId,
				},
				SessionProgram: ssh.Shell,
			},
			wantErr: nil,
		},
		{
			name:     "unsupported session program - subsystem",
			id:       "21234567890",
			protocol: ssh.Protocol,
			chs: &ssh.ChannelSummary{
				ChannelSummary: &bsr.BaseChannelSummary{
					Id:                    channelId,
					ConnectionRecordingId: connectionId,
				},
				SessionProgram: ssh.Subsystem,
			},
			wantErr: errors.New("convert.ToAsciicast: unsupported \"subsystem\" session program for asciicast conversion"),
		},
		{
			name:     "unsupported session program - not applicable",
			id:       "21234567892",
			protocol: ssh.Protocol,
			chs: &ssh.ChannelSummary{
				ChannelSummary: &bsr.BaseChannelSummary{
					Id:                    channelId,
					ConnectionRecordingId: connectionId,
				},
				SessionProgram: ssh.NotApplicable,
			},
			wantErr: errors.New("convert.ToAsciicast: unsupported \"not applicable\" session program for asciicast conversion"),
		},
		{
			name:     "unsupported session program - none",
			id:       "21234567891",
			protocol: ssh.Protocol,
			chs: &ssh.ChannelSummary{
				ChannelSummary: &bsr.BaseChannelSummary{
					Id:                    channelId,
					ConnectionRecordingId: connectionId,
				},
				SessionProgram: ssh.None,
			},
			wantErr: errors.New("convert.ToAsciicast: unsupported \"none\" session program for asciicast conversion"),
		},
		{
			name:     "nil session program",
			id:       "31234567890",
			protocol: ssh.Protocol,
			chs: &ssh.ChannelSummary{
				ChannelSummary: &bsr.BaseChannelSummary{
					Id:                    channelId,
					ConnectionRecordingId: connectionId,
				},
			},
			wantErr: errors.New("convert.ToAsciicast: session program not set for asciicast conversion"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup keys
			keys, err := kms.CreateKeys(ctx, kms.TestWrapper(t), fmt.Sprintf("s_%s", tc.id))
			require.NoError(t, err)

			keyFn := func(w kms.WrappedKeys) (kms.UnwrappedKeys, error) {
				u := kms.UnwrappedKeys{
					BsrKey:  keys.BsrKey,
					PrivKey: keys.PrivKey,
				}
				return u, nil
			}

			// Set up session
			srm := &bsr.SessionRecordingMeta{
				Id:       fmt.Sprintf("sr_%s", tc.id),
				Protocol: tc.protocol,
			}
			sessionMeta := bsr.TestSessionMeta(fmt.Sprintf("s_%s", tc.id))

			sesh, err := bsr.NewSession(ctx, srm, sessionMeta, fs, keys, bsr.WithSupportsMultiplex(true))
			require.NoError(t, err)
			require.NotNil(t, sesh)

			// Encode session summary
			sesh.EncodeSummary(ctx, &bsr.BaseSessionSummary{
				Id: channelId,
			})

			// Set up connection
			connMeta := &bsr.ConnectionRecordingMeta{Id: connectionId}
			conn, err := sesh.NewConnection(ctx, connMeta)
			require.NoError(t, err)
			require.NotNil(t, conn)

			// Encode connection summary
			err = conn.EncodeSummary(ctx, &bsr.BaseConnectionSummary{
				Id:           connectionId,
				ChannelCount: 1,
			})
			require.NoError(t, err)

			// Setup Channel
			chanMeta := &bsr.ChannelRecordingMeta{
				Id:   channelId,
				Type: "chan",
			}
			ch, err := conn.NewChannel(ctx, chanMeta)
			require.NoError(t, err)
			require.NotNil(t, ch)

			// Encode channel summary
			err = ch.EncodeSummary(ctx, tc.chs)
			require.NoError(t, err)

			// Write request-inbound.data file
			requestInboundBsrChunks := testChunks(fmt.Sprintf("s_%s", tc.id), bsr.Inbound, tc.protocol)
			inW, err := ch.NewRequestsWriter(ctx, bsr.Inbound)
			require.NoError(t, err)
			require.NotNil(t, inW)

			writeToChannels(ctx, inW, requestInboundBsrChunks...)
			require.NoError(t, err)

			inWC := inW.(io.Closer)
			inWC.Close()

			// Write message-outbound.data file
			messageOutboundBsrChunks := testChunks(fmt.Sprintf("s_%s", tc.id), bsr.Outbound, tc.protocol)
			outW, err := ch.NewMessagesWriter(ctx, bsr.Outbound)
			require.NoError(t, err)
			require.NotNil(t, outW)

			err = writeToChannels(ctx, outW, messageOutboundBsrChunks...)
			require.NoError(t, err)

			require.NoError(t, ch.Close(ctx))
			require.NoError(t, conn.Close(ctx))
			require.NoError(t, sesh.Close(ctx))

			opSesh, err := bsr.OpenSession(ctx, srm.Id, fs, keyFn)
			require.NoError(t, err)
			require.NotNil(t, opSesh)

			_, err = convert.ToAsciicast(ctx, opSesh, tmpfile, connectionId, convert.WithChannelId(channelId))
			if tc.wantErr != nil {
				require.EqualError(t, err, tc.wantErr.Error())
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestConvert_ToAsciicast_Protocol(t *testing.T) {
	ctx := context.Background()

	fs := &fstest.MemFS{}
	tmpfile, err := fstest.NewTempFile(t.Name())
	require.NoError(t, err)

	connectionId := "test_connection"
	channelId := "test_channel"

	cases := []struct {
		name                 string
		protocol             bsr.Protocol
		registerSummaryAlloc bool
		id                   string
		wantErr              error
	}{
		{
			name:                 "unsupported protocol",
			id:                   "41234567890",
			protocol:             bsr.Protocol("UNSUPPORTED_PROTOCOL"),
			registerSummaryAlloc: true,
			wantErr:              errors.New("convert.ToAsciicast: unsupported protocol"),
		},
		{
			name:                 "BSSH Protocol",
			id:                   "51234567890",
			protocol:             ssh.Protocol,
			registerSummaryAlloc: false,
			wantErr:              nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup keys
			keys, err := kms.CreateKeys(ctx, kms.TestWrapper(t), fmt.Sprintf("s_%s", tc.id))
			require.NoError(t, err)

			keyFn := func(w kms.WrappedKeys) (kms.UnwrappedKeys, error) {
				u := kms.UnwrappedKeys{
					BsrKey:  keys.BsrKey,
					PrivKey: keys.PrivKey,
				}
				return u, nil
			}

			// Register custom summary alloc func for custom protocol
			if tc.registerSummaryAlloc {
				err = bsr.RegisterSummaryAllocFunc(tc.protocol, bsr.ChannelContainer, func(ctx context.Context) bsr.Summary {
					return &bsr.BaseChannelSummary{Id: channelId, ConnectionRecordingId: connectionId}
				})
				require.NoError(t, err)

				err = bsr.RegisterSummaryAllocFunc(tc.protocol, bsr.SessionContainer, func(ctx context.Context) bsr.Summary {
					return &bsr.BaseSessionSummary{Id: fmt.Sprintf("s_%s", tc.id), ConnectionCount: 1}
				})
				require.NoError(t, err)

				err = bsr.RegisterSummaryAllocFunc(tc.protocol, bsr.ConnectionContainer, func(ctx context.Context) bsr.Summary {
					return &bsr.BaseConnectionSummary{Id: connectionId, ChannelCount: 1}
				})
				require.NoError(t, err)
			}

			// Set up session
			srm := &bsr.SessionRecordingMeta{
				Id:       fmt.Sprintf("sr_%s", tc.id),
				Protocol: tc.protocol,
			}
			sessionMeta := bsr.TestSessionMeta(fmt.Sprintf("s_%s", tc.id))

			sesh, err := bsr.NewSession(ctx, srm, sessionMeta, fs, keys, bsr.WithSupportsMultiplex(true))
			require.NoError(t, err)
			require.NotNil(t, sesh)

			// Encode session summary
			sesh.EncodeSummary(ctx, &bsr.BaseSessionSummary{
				Id: channelId,
			})

			// Set up connection
			connMeta := &bsr.ConnectionRecordingMeta{Id: connectionId}
			conn, err := sesh.NewConnection(ctx, connMeta)
			require.NoError(t, err)
			require.NotNil(t, conn)

			// Encode connection summary
			err = conn.EncodeSummary(ctx, &bsr.BaseConnectionSummary{
				Id:           connectionId,
				ChannelCount: 1,
			})
			require.NoError(t, err)

			// Setup Channel
			chanMeta := &bsr.ChannelRecordingMeta{
				Id:   channelId,
				Type: "chan",
			}
			ch, err := conn.NewChannel(ctx, chanMeta)
			require.NoError(t, err)
			require.NotNil(t, ch)

			// Encode channel summary
			err = ch.EncodeSummary(ctx, &ssh.ChannelSummary{
				ChannelSummary: &bsr.BaseChannelSummary{
					Id:                    channelId,
					ConnectionRecordingId: connectionId,
				},
				SessionProgram: ssh.Shell,
			})
			require.NoError(t, err)

			// Write request-inbound.data file
			requestInboundBsrChunks := testChunks(fmt.Sprintf("s_%s", tc.id), bsr.Inbound, tc.protocol)
			inW, err := ch.NewRequestsWriter(ctx, bsr.Inbound)
			require.NoError(t, err)
			require.NotNil(t, inW)

			writeToChannels(ctx, inW, requestInboundBsrChunks...)
			require.NoError(t, err)

			inWC := inW.(io.Closer)
			inWC.Close()

			// Write message-outbound.data file
			messageOutboundBsrChunks := testChunks(fmt.Sprintf("s_%s", tc.id), bsr.Outbound, tc.protocol)
			outW, err := ch.NewMessagesWriter(ctx, bsr.Outbound)
			require.NoError(t, err)
			require.NotNil(t, outW)

			err = writeToChannels(ctx, outW, messageOutboundBsrChunks...)
			require.NoError(t, err)

			outWC := outW.(io.Closer)
			outWC.Close()

			ch.Close(ctx)
			conn.Close(ctx)
			sesh.Close(ctx)

			opSesh, err := bsr.OpenSession(ctx, srm.Id, fs, keyFn)
			require.NoError(t, err)
			require.NotNil(t, opSesh)

			_, err = convert.ToAsciicast(ctx, opSesh, tmpfile, connectionId, convert.WithChannelId(channelId))
			if tc.wantErr != nil {
				require.EqualError(t, err, tc.wantErr.Error())
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestConvert_ToAsciicast_Scanner(t *testing.T) {
	ctx := context.Background()

	fs := &fstest.MemFS{}
	tmpfile, err := fstest.NewTempFile(t.Name())
	require.NoError(t, err)

	connectionId := "test_connection"
	channelId := "test_channel"

	cases := []struct {
		name         string
		protocol     bsr.Protocol
		writeRequest bool
		writeMessage bool
		id           string
		wantErr      error
	}{
		{
			name:         "request and message scanner",
			id:           "61234567890",
			protocol:     ssh.Protocol,
			writeRequest: true,
			writeMessage: true,
			wantErr:      nil,
		},
		{
			name:         "missing requests data file",
			id:           "71234567890",
			protocol:     ssh.Protocol,
			writeRequest: false,
			writeMessage: true,
			wantErr:      errors.New("convert.ToAsciicast: bsr.(Channel).OpenRequestScanner: file requests-inbound.data does not exist: does not exist"),
		},
		{
			name:         "missing messages data file",
			id:           "81234567890",
			protocol:     ssh.Protocol,
			writeRequest: true,
			writeMessage: false,
			wantErr:      errors.New("convert.ToAsciicast: bsr.(Channel).OpenMessageScanner: file messages-outbound.data does not exist: does not exist"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup keys
			keys, err := kms.CreateKeys(ctx, kms.TestWrapper(t), fmt.Sprintf("s_%s", tc.id))
			require.NoError(t, err)

			keyFn := func(w kms.WrappedKeys) (kms.UnwrappedKeys, error) {
				u := kms.UnwrappedKeys{
					BsrKey:  keys.BsrKey,
					PrivKey: keys.PrivKey,
				}
				return u, nil
			}

			// Set up session
			srm := &bsr.SessionRecordingMeta{
				Id:       fmt.Sprintf("sr_%s", tc.id),
				Protocol: tc.protocol,
			}
			sessionMeta := bsr.TestSessionMeta(fmt.Sprintf("s_%s", tc.id))

			sesh, err := bsr.NewSession(ctx, srm, sessionMeta, fs, keys, bsr.WithSupportsMultiplex(true))
			require.NoError(t, err)
			require.NotNil(t, sesh)

			// Encode session summary
			sesh.EncodeSummary(ctx, &bsr.BaseSessionSummary{
				Id: channelId,
			})

			// Set up connection
			connMeta := &bsr.ConnectionRecordingMeta{Id: connectionId}
			conn, err := sesh.NewConnection(ctx, connMeta)
			require.NoError(t, err)
			require.NotNil(t, conn)

			// Encode connection summary
			err = conn.EncodeSummary(ctx, &bsr.BaseConnectionSummary{
				Id:           connectionId,
				ChannelCount: 1,
			})
			require.NoError(t, err)

			// Setup Channel
			chanMeta := &bsr.ChannelRecordingMeta{
				Id:   channelId,
				Type: "chan",
			}
			ch, err := conn.NewChannel(ctx, chanMeta)
			require.NoError(t, err)
			require.NotNil(t, ch)

			// Encode channel summary
			err = ch.EncodeSummary(ctx, &ssh.ChannelSummary{
				ChannelSummary: &bsr.BaseChannelSummary{
					Id:                    channelId,
					ConnectionRecordingId: connectionId,
				},
				SessionProgram: ssh.Shell,
			})
			require.NoError(t, err)

			if tc.writeRequest {
				// Write request-inbound.data file
				requestInboundBsrChunks := testChunks(fmt.Sprintf("s_%s", tc.id), bsr.Inbound, tc.protocol)
				inW, err := ch.NewRequestsWriter(ctx, bsr.Inbound)
				require.NoError(t, err)
				require.NotNil(t, inW)

				writeToChannels(ctx, inW, requestInboundBsrChunks...)
				require.NoError(t, err)

				inWC := inW.(io.Closer)
				inWC.Close()
			}

			if tc.writeMessage {
				// Write message-outbound.data file
				messageOutboundBsrChunks := testChunks(fmt.Sprintf("s_%s", tc.id), bsr.Outbound, tc.protocol)
				outW, err := ch.NewMessagesWriter(ctx, bsr.Outbound)
				require.NoError(t, err)
				require.NotNil(t, outW)

				err = writeToChannels(ctx, outW, messageOutboundBsrChunks...)
				require.NoError(t, err)

				outWC := outW.(io.Closer)
				outWC.Close()
			}

			ch.Close(ctx)
			conn.Close(ctx)
			sesh.Close(ctx)

			opSesh, err := bsr.OpenSession(ctx, srm.Id, fs, keyFn)
			require.NoError(t, err)
			require.NotNil(t, opSesh)

			_, err = convert.ToAsciicast(ctx, opSesh, tmpfile, connectionId, convert.WithChannelId(channelId))
			if tc.wantErr != nil {
				require.EqualError(t, err, tc.wantErr.Error())
				return
			}
			require.NoError(t, err)
		})
	}
}
