// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

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
	"github.com/stretchr/testify/require"
)

func TestConvert_ToAsciicast(t *testing.T) {
	ctx := context.Background()

	fs := &fstest.MemFS{}
	tmpfile, err := fstest.NewTempFile(t.Name())
	require.NoError(t, err)
	ts := time.Date(2023, time.March, 16, 10, 47, 3, 14, time.UTC)

	connectionId := "test_connection"
	channelId := "test_channel"

	writeToChannel := func(w io.Writer, chunks ...bsr.Chunk) {
		w.Write(bsr.Magic.Bytes())
		enc, err := bsr.NewChunkEncoder(ctx, w, bsr.NoCompression, bsr.NoEncryption)
		require.NoError(t, err)

		for _, c := range chunks {
			_, err := enc.Encode(ctx, c)
			require.NoError(t, err)
		}
	}

	cases := []struct {
		name                 string
		cs                   bsr.ChannelSummary
		bsrChunk             []bsr.Chunk
		protocol             bsr.Protocol
		registerSummaryAlloc bool
		id                   string
		wantErr              error
	}{
		{
			name:     "exec",
			id:       "01234567890",
			protocol: ssh.Protocol,
			cs: &ssh.ChannelSummary{
				ChannelSummary: &bsr.BaseChannelSummary{
					Id:                    channelId,
					ConnectionRecordingId: connectionId,
				},
				SessionProgram: ssh.Exec,
			},
			bsrChunk: []bsr.Chunk{
				&bsr.HeaderChunk{
					BaseChunk: &bsr.BaseChunk{
						Protocol:  ssh.Protocol,
						Direction: bsr.Inbound,
						Timestamp: bsr.NewTimestamp(ts),
						Type:      bsr.ChunkHeader,
					},
					Compression: bsr.NoCompression,
					Encryption:  bsr.NoEncryption,
					SessionId:   "s_01234567890",
				},
				&bsr.EndChunk{
					BaseChunk: &bsr.BaseChunk{
						Protocol:  ssh.Protocol,
						Direction: bsr.Inbound,
						Timestamp: bsr.NewTimestamp(ts.Add(time.Second)),
						Type:      bsr.ChunkEnd,
					},
				},
			},
			wantErr: nil,
		},
		{
			name:     "shell",
			id:       "11234567890",
			protocol: ssh.Protocol,
			cs: &ssh.ChannelSummary{
				ChannelSummary: &bsr.BaseChannelSummary{
					Id:                    channelId,
					ConnectionRecordingId: connectionId,
				},
				SessionProgram: ssh.Shell,
			},
			bsrChunk: []bsr.Chunk{
				&bsr.HeaderChunk{
					BaseChunk: &bsr.BaseChunk{
						Protocol:  ssh.Protocol,
						Direction: bsr.Inbound,
						Timestamp: bsr.NewTimestamp(ts),
						Type:      bsr.ChunkHeader,
					},
					Compression: bsr.NoCompression,
					Encryption:  bsr.NoEncryption,
					SessionId:   "s_11234567890",
				},
				&bsr.EndChunk{
					BaseChunk: &bsr.BaseChunk{
						Protocol:  ssh.Protocol,
						Direction: bsr.Inbound,
						Timestamp: bsr.NewTimestamp(ts.Add(time.Second)),
						Type:      bsr.ChunkEnd,
					},
				},
			},
			wantErr: nil,
		},
		{
			name:     "unsupported session program",
			id:       "21234567890",
			protocol: ssh.Protocol,
			cs: &ssh.ChannelSummary{
				ChannelSummary: &bsr.BaseChannelSummary{
					Id:                    channelId,
					ConnectionRecordingId: connectionId,
				},
				SessionProgram: ssh.Subsystem,
			},
			bsrChunk: []bsr.Chunk{
				&bsr.HeaderChunk{
					BaseChunk: &bsr.BaseChunk{
						Protocol:  ssh.Protocol,
						Direction: bsr.Inbound,
						Timestamp: bsr.NewTimestamp(ts),
						Type:      bsr.ChunkHeader,
					},
					Compression: bsr.NoCompression,
					Encryption:  bsr.NoEncryption,
					SessionId:   "s_21234567890",
				},
				&bsr.EndChunk{
					BaseChunk: &bsr.BaseChunk{
						Protocol:  ssh.Protocol,
						Direction: bsr.Inbound,
						Timestamp: bsr.NewTimestamp(ts.Add(time.Second)),
						Type:      bsr.ChunkEnd,
					},
				},
			},
			wantErr: errors.New("convert.ToAsciicast: unsupported \"subsystem\" session program for asciicast conversion"),
		},
		{
			name:     "nil session program",
			id:       "31234567890",
			protocol: ssh.Protocol,
			cs: &ssh.ChannelSummary{
				ChannelSummary: &bsr.BaseChannelSummary{
					Id:                    channelId,
					ConnectionRecordingId: connectionId,
				},
			},
			bsrChunk: []bsr.Chunk{
				&bsr.HeaderChunk{
					BaseChunk: &bsr.BaseChunk{
						Protocol:  ssh.Protocol,
						Direction: bsr.Inbound,
						Timestamp: bsr.NewTimestamp(ts),
						Type:      bsr.ChunkHeader,
					},
					Compression: bsr.NoCompression,
					Encryption:  bsr.NoEncryption,
					SessionId:   "s_31234567890",
				},
				&bsr.EndChunk{
					BaseChunk: &bsr.BaseChunk{
						Protocol:  ssh.Protocol,
						Direction: bsr.Inbound,
						Timestamp: bsr.NewTimestamp(ts.Add(time.Second)),
						Type:      bsr.ChunkEnd,
					},
				},
			},
			wantErr: errors.New("convert.ToAsciicast: session program not set for asciicast conversion"),
		},
		{
			name:                 "unsupported protocol",
			id:                   "41234567890",
			protocol:             bsr.Protocol("UNSUPPORTED_PROTOCOL"),
			registerSummaryAlloc: true,
			cs: &ssh.ChannelSummary{
				ChannelSummary: &bsr.BaseChannelSummary{
					Id:                    channelId,
					ConnectionRecordingId: connectionId,
				},
			},
			bsrChunk: []bsr.Chunk{
				&bsr.HeaderChunk{
					BaseChunk: &bsr.BaseChunk{
						Protocol:  bsr.Protocol("UNSUPPORTED_PROTOCOL"),
						Direction: bsr.Inbound,
						Timestamp: bsr.NewTimestamp(ts),
						Type:      bsr.ChunkHeader,
					},
					Compression: bsr.NoCompression,
					Encryption:  bsr.NoEncryption,
					SessionId:   "s_41234567890",
				},
				&bsr.EndChunk{
					BaseChunk: &bsr.BaseChunk{
						Protocol:  bsr.Protocol("UNSUPPORTED_PROTOCOL"),
						Direction: bsr.Inbound,
						Timestamp: bsr.NewTimestamp(ts.Add(time.Second)),
						Type:      bsr.ChunkEnd,
					},
				},
			},
			wantErr: errors.New("convert.ToAsciicast: unsupported protocol"),
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
			err = ch.EncodeSummary(ctx, tc.cs)
			require.NoError(t, err)

			// Write request-inbound.data file
			inW, err := ch.NewRequestsWriter(ctx, bsr.Inbound)
			require.NoError(t, err)
			require.NotNil(t, inW)

			writeToChannel(inW, tc.bsrChunk...)
			inWC := inW.(io.Closer)
			inWC.Close()

			// Write message-outbound.data file
			outW, err := ch.NewMessagesWriter(ctx, bsr.Outbound)
			require.NoError(t, err)
			require.NotNil(t, outW)

			writeToChannel(outW, tc.bsrChunk...)
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
