// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package convert

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/bsr"
	sshv1 "github.com/hashicorp/boundary/internal/bsr/gen/ssh/v1"
	"github.com/hashicorp/boundary/internal/bsr/internal/fstest"
	"github.com/hashicorp/boundary/internal/bsr/ssh"
	"github.com/stretchr/testify/require"
)

func Test_sshChannelToAsciicast(t *testing.T) {
	ctx := context.Background()

	ts := time.Date(2023, time.March, 16, 10, 47, 3, 14, time.UTC)
	newW := func() io.ReadWriteSeeker {
		f, err := os.CreateTemp("", "*.asciicast")
		require.NoError(t, err)
		t.Cleanup(func() {
			os.Remove(f.Name())
		})
		return f
	}
	newScanner := func(chunks ...bsr.Chunk) *bsr.ChunkScanner {
		buf, err := fstest.NewTempBuffer()
		require.NoError(t, err)
		buf.Write(bsr.Magic.Bytes())
		enc, err := bsr.NewChunkEncoder(ctx, buf, bsr.NoCompression, bsr.NoEncryption)
		require.NoError(t, err)

		for _, c := range chunks {
			_, err := enc.Encode(ctx, c)
			require.NoError(t, err)
		}
		s, err := bsr.NewChunkScanner(ctx, bytes.NewBuffer(buf.Bytes()))
		require.NoError(t, err)
		return s
	}
	cases := []struct {
		name           string
		requestScanner *bsr.ChunkScanner
		messageScanner *bsr.ChunkScanner
		w              io.ReadWriteSeeker
		opts           []Option
		want           []byte
		wantErr        error
	}{
		{
			"no-pty-no-env-no-messages",
			newScanner(
				&bsr.HeaderChunk{
					BaseChunk: &bsr.BaseChunk{
						Protocol:  ssh.Protocol,
						Direction: bsr.Inbound,
						Timestamp: bsr.NewTimestamp(ts),
						Type:      bsr.ChunkHeader,
					},
					Compression: bsr.NoCompression,
					Encryption:  bsr.NoEncryption,
					SessionId:   "sess_123456789",
				},
				&bsr.EndChunk{
					BaseChunk: &bsr.BaseChunk{
						Protocol:  ssh.Protocol,
						Direction: bsr.Inbound,
						Timestamp: bsr.NewTimestamp(ts.Add(time.Second)),
						Type:      bsr.ChunkEnd,
					},
				},
			),
			newScanner(
				&bsr.HeaderChunk{
					BaseChunk: &bsr.BaseChunk{
						Protocol:  ssh.Protocol,
						Direction: bsr.Inbound,
						Timestamp: bsr.NewTimestamp(ts),
						Type:      bsr.ChunkHeader,
					},
					Compression: bsr.NoCompression,
					Encryption:  bsr.NoEncryption,
					SessionId:   "sess_123456789",
				},
				&bsr.EndChunk{
					BaseChunk: &bsr.BaseChunk{
						Protocol:  ssh.Protocol,
						Direction: bsr.Inbound,
						Timestamp: bsr.NewTimestamp(ts.Add(time.Second)),
						Type:      bsr.ChunkEnd,
					},
				},
			),
			newW(),
			nil,
			[]byte(`{"version":2,"width":80,"height":24,"timestamp":1678963623,"env":{"SHELL":"/bin/bash","TERM":"xterm"}}
`),
			nil,
		},
		{
			"pty-no-env-no-messages",
			newScanner(
				&bsr.HeaderChunk{
					BaseChunk: &bsr.BaseChunk{
						Protocol:  ssh.Protocol,
						Direction: bsr.Inbound,
						Timestamp: bsr.NewTimestamp(ts),
						Type:      bsr.ChunkHeader,
					},
					Compression: bsr.NoCompression,
					Encryption:  bsr.NoEncryption,
					SessionId:   "sess_123456789",
				},
				&ssh.PtyRequest{
					BaseChunk: &bsr.BaseChunk{
						Protocol:  ssh.Protocol,
						Direction: bsr.Inbound,
						Timestamp: bsr.NewTimestamp(ts.Add(time.Microsecond)),
						Type:      ssh.PtyReqChunkType,
					},
					PtyRequest: &sshv1.PtyRequest{
						RequestType:             ssh.PtyRequestType,
						WantReply:               false,
						TermEnvVar:              "kitty",
						TerminalWidthCharacters: 160,
						TerminalHeightRows:      200,
						TerminalWidthPixels:     0,
						TerminalHeightPixels:    0,
						EncodedTerminalMode:     []byte{},
					},
				},
				&bsr.EndChunk{
					BaseChunk: &bsr.BaseChunk{
						Protocol:  ssh.Protocol,
						Direction: bsr.Inbound,
						Timestamp: bsr.NewTimestamp(ts.Add(time.Second)),
						Type:      bsr.ChunkEnd,
					},
				},
			),
			newScanner(
				&bsr.HeaderChunk{
					BaseChunk: &bsr.BaseChunk{
						Protocol:  ssh.Protocol,
						Direction: bsr.Inbound,
						Timestamp: bsr.NewTimestamp(ts),
						Type:      bsr.ChunkHeader,
					},
					Compression: bsr.NoCompression,
					Encryption:  bsr.NoEncryption,
					SessionId:   "sess_123456789",
				},
				&bsr.EndChunk{
					BaseChunk: &bsr.BaseChunk{
						Protocol:  ssh.Protocol,
						Direction: bsr.Inbound,
						Timestamp: bsr.NewTimestamp(ts.Add(time.Second)),
						Type:      bsr.ChunkEnd,
					},
				},
			),
			newW(),
			nil,
			[]byte(`{"version":2,"width":160,"height":200,"timestamp":1678963623,"env":{"SHELL":"/bin/bash","TERM":"kitty"}}
`),
			nil,
		},
		{
			"tiny-pty-no-env-no-messages",
			newScanner(
				&bsr.HeaderChunk{
					BaseChunk: &bsr.BaseChunk{
						Protocol:  ssh.Protocol,
						Direction: bsr.Inbound,
						Timestamp: bsr.NewTimestamp(ts),
						Type:      bsr.ChunkHeader,
					},
					Compression: bsr.NoCompression,
					Encryption:  bsr.NoEncryption,
					SessionId:   "sess_123456789",
				},
				&ssh.PtyRequest{
					BaseChunk: &bsr.BaseChunk{
						Protocol:  ssh.Protocol,
						Direction: bsr.Inbound,
						Timestamp: bsr.NewTimestamp(ts.Add(time.Microsecond)),
						Type:      ssh.PtyReqChunkType,
					},
					PtyRequest: &sshv1.PtyRequest{
						RequestType:             ssh.PtyRequestType,
						WantReply:               false,
						TermEnvVar:              "kitty",
						TerminalWidthCharacters: 2,
						TerminalHeightRows:      2,
						TerminalWidthPixels:     0,
						TerminalHeightPixels:    0,
						EncodedTerminalMode:     []byte{},
					},
				},
				&bsr.EndChunk{
					BaseChunk: &bsr.BaseChunk{
						Protocol:  ssh.Protocol,
						Direction: bsr.Inbound,
						Timestamp: bsr.NewTimestamp(ts.Add(time.Second)),
						Type:      bsr.ChunkEnd,
					},
				},
			),
			newScanner(
				&bsr.HeaderChunk{
					BaseChunk: &bsr.BaseChunk{
						Protocol:  ssh.Protocol,
						Direction: bsr.Inbound,
						Timestamp: bsr.NewTimestamp(ts),
						Type:      bsr.ChunkHeader,
					},
					Compression: bsr.NoCompression,
					Encryption:  bsr.NoEncryption,
					SessionId:   "sess_123456789",
				},
				&bsr.EndChunk{
					BaseChunk: &bsr.BaseChunk{
						Protocol:  ssh.Protocol,
						Direction: bsr.Inbound,
						Timestamp: bsr.NewTimestamp(ts.Add(time.Second)),
						Type:      bsr.ChunkEnd,
					},
				},
			),
			newW(),
			nil,
			[]byte(`{"version":2,"width":2,"height":2,"timestamp":1678963623,"env":{"SHELL":"/bin/bash","TERM":"kitty"}}
`),
			nil,
		},
		{
			"tiny-pty-no-env-no-messages-min-width-min-height",
			newScanner(
				&bsr.HeaderChunk{
					BaseChunk: &bsr.BaseChunk{
						Protocol:  ssh.Protocol,
						Direction: bsr.Inbound,
						Timestamp: bsr.NewTimestamp(ts),
						Type:      bsr.ChunkHeader,
					},
					Compression: bsr.NoCompression,
					Encryption:  bsr.NoEncryption,
					SessionId:   "sess_123456789",
				},
				&ssh.PtyRequest{
					BaseChunk: &bsr.BaseChunk{
						Protocol:  ssh.Protocol,
						Direction: bsr.Inbound,
						Timestamp: bsr.NewTimestamp(ts.Add(time.Microsecond)),
						Type:      ssh.PtyReqChunkType,
					},
					PtyRequest: &sshv1.PtyRequest{
						RequestType:             ssh.PtyRequestType,
						WantReply:               false,
						TermEnvVar:              "kitty",
						TerminalWidthCharacters: 2,
						TerminalHeightRows:      2,
						TerminalWidthPixels:     0,
						TerminalHeightPixels:    0,
						EncodedTerminalMode:     []byte{},
					},
				},
				&bsr.EndChunk{
					BaseChunk: &bsr.BaseChunk{
						Protocol:  ssh.Protocol,
						Direction: bsr.Inbound,
						Timestamp: bsr.NewTimestamp(ts.Add(time.Second)),
						Type:      bsr.ChunkEnd,
					},
				},
			),
			newScanner(
				&bsr.HeaderChunk{
					BaseChunk: &bsr.BaseChunk{
						Protocol:  ssh.Protocol,
						Direction: bsr.Inbound,
						Timestamp: bsr.NewTimestamp(ts),
						Type:      bsr.ChunkHeader,
					},
					Compression: bsr.NoCompression,
					Encryption:  bsr.NoEncryption,
					SessionId:   "sess_123456789",
				},
				&bsr.EndChunk{
					BaseChunk: &bsr.BaseChunk{
						Protocol:  ssh.Protocol,
						Direction: bsr.Inbound,
						Timestamp: bsr.NewTimestamp(ts.Add(time.Second)),
						Type:      bsr.ChunkEnd,
					},
				},
			),
			newW(),
			[]Option{WithMinWidth(60), WithMinHeight(26)},
			[]byte(`{"version":2,"width":60,"height":26,"timestamp":1678963623,"env":{"SHELL":"/bin/bash","TERM":"kitty"}}
`),
			nil,
		},
		{
			"pty-no-env-no-messages-window-change",
			newScanner(
				&bsr.HeaderChunk{
					BaseChunk: &bsr.BaseChunk{
						Protocol:  ssh.Protocol,
						Direction: bsr.Inbound,
						Timestamp: bsr.NewTimestamp(ts),
						Type:      bsr.ChunkHeader,
					},
					Compression: bsr.NoCompression,
					Encryption:  bsr.NoEncryption,
					SessionId:   "sess_123456789",
				},
				&ssh.PtyRequest{
					BaseChunk: &bsr.BaseChunk{
						Protocol:  ssh.Protocol,
						Direction: bsr.Inbound,
						Timestamp: bsr.NewTimestamp(ts.Add(time.Microsecond)),
						Type:      ssh.PtyReqChunkType,
					},
					PtyRequest: &sshv1.PtyRequest{
						RequestType:             ssh.PtyRequestType,
						WantReply:               false,
						TermEnvVar:              "kitty",
						TerminalWidthCharacters: 160,
						TerminalHeightRows:      200,
						TerminalWidthPixels:     0,
						TerminalHeightPixels:    0,
						EncodedTerminalMode:     []byte{},
					},
				},
				&ssh.WindowChangeRequest{
					BaseChunk: &bsr.BaseChunk{
						Protocol:  ssh.Protocol,
						Direction: bsr.Inbound,
						Timestamp: bsr.NewTimestamp(ts.Add(time.Microsecond)),
						Type:      ssh.WindowChangeReqChunkType,
					},
					WindowChangeRequest: &sshv1.WindowChangeRequest{
						RequestType:          ssh.WindowChangeRequestType,
						WantReply:            false,
						TerminalWidthColumns: 220,
						TerminalHeightRows:   100,
					},
				},
				&ssh.WindowChangeRequest{
					BaseChunk: &bsr.BaseChunk{
						Protocol:  ssh.Protocol,
						Direction: bsr.Inbound,
						Timestamp: bsr.NewTimestamp(ts.Add(time.Microsecond)),
						Type:      ssh.WindowChangeReqChunkType,
					},
					WindowChangeRequest: &sshv1.WindowChangeRequest{
						RequestType:          ssh.WindowChangeRequestType,
						WantReply:            false,
						TerminalWidthColumns: 100,
						TerminalHeightRows:   500,
					},
				},
				&bsr.EndChunk{
					BaseChunk: &bsr.BaseChunk{
						Protocol:  ssh.Protocol,
						Direction: bsr.Inbound,
						Timestamp: bsr.NewTimestamp(ts.Add(time.Second)),
						Type:      bsr.ChunkEnd,
					},
				},
			),
			newScanner(
				&bsr.HeaderChunk{
					BaseChunk: &bsr.BaseChunk{
						Protocol:  ssh.Protocol,
						Direction: bsr.Inbound,
						Timestamp: bsr.NewTimestamp(ts),
						Type:      bsr.ChunkHeader,
					},
					Compression: bsr.NoCompression,
					Encryption:  bsr.NoEncryption,
					SessionId:   "sess_123456789",
				},
				&bsr.EndChunk{
					BaseChunk: &bsr.BaseChunk{
						Protocol:  ssh.Protocol,
						Direction: bsr.Inbound,
						Timestamp: bsr.NewTimestamp(ts.Add(time.Second)),
						Type:      bsr.ChunkEnd,
					},
				},
			),
			newW(),
			nil,
			[]byte(`{"version":2,"width":220,"height":500,"timestamp":1678963623,"env":{"SHELL":"/bin/bash","TERM":"kitty"}}
`),
			nil,
		},
		{
			"pty-env-no-messages",
			newScanner(
				&bsr.HeaderChunk{
					BaseChunk: &bsr.BaseChunk{
						Protocol:  ssh.Protocol,
						Direction: bsr.Inbound,
						Timestamp: bsr.NewTimestamp(ts),
						Type:      bsr.ChunkHeader,
					},
					Compression: bsr.NoCompression,
					Encryption:  bsr.NoEncryption,
					SessionId:   "sess_123456789",
				},
				&ssh.PtyRequest{
					BaseChunk: &bsr.BaseChunk{
						Protocol:  ssh.Protocol,
						Direction: bsr.Inbound,
						Timestamp: bsr.NewTimestamp(ts.Add(time.Microsecond)),
						Type:      ssh.PtyReqChunkType,
					},
					PtyRequest: &sshv1.PtyRequest{
						RequestType:             ssh.PtyRequestType,
						WantReply:               false,
						TermEnvVar:              "kitty",
						TerminalWidthCharacters: 160,
						TerminalHeightRows:      200,
						TerminalWidthPixels:     0,
						TerminalHeightPixels:    0,
						EncodedTerminalMode:     []byte{},
					},
				},
				&ssh.EnvRequest{
					BaseChunk: &bsr.BaseChunk{
						Protocol:  ssh.Protocol,
						Direction: bsr.Inbound,
						Timestamp: bsr.NewTimestamp(ts.Add(time.Microsecond + time.Nanosecond)),
						Type:      ssh.EnvReqChunkType,
					},
					EnvRequest: &sshv1.EnvRequest{
						RequestType:   ssh.EnvRequestType,
						WantReply:     false,
						VariableName:  "SHELL",
						VariableValue: "/bin/fish",
					},
				},
				&bsr.EndChunk{
					BaseChunk: &bsr.BaseChunk{
						Protocol:  ssh.Protocol,
						Direction: bsr.Inbound,
						Timestamp: bsr.NewTimestamp(ts.Add(time.Second)),
						Type:      bsr.ChunkEnd,
					},
				},
			),
			newScanner(
				&bsr.HeaderChunk{
					BaseChunk: &bsr.BaseChunk{
						Protocol:  ssh.Protocol,
						Direction: bsr.Inbound,
						Timestamp: bsr.NewTimestamp(ts),
						Type:      bsr.ChunkHeader,
					},
					Compression: bsr.NoCompression,
					Encryption:  bsr.NoEncryption,
					SessionId:   "sess_123456789",
				},
				&bsr.EndChunk{
					BaseChunk: &bsr.BaseChunk{
						Protocol:  ssh.Protocol,
						Direction: bsr.Inbound,
						Timestamp: bsr.NewTimestamp(ts.Add(time.Second)),
						Type:      bsr.ChunkEnd,
					},
				},
			),
			newW(),
			nil,
			[]byte(`{"version":2,"width":160,"height":200,"timestamp":1678963623,"env":{"SHELL":"/bin/fish","TERM":"kitty"}}
`),
			nil,
		},
		{
			"no-pty-no-env-messages",
			newScanner(
				&bsr.HeaderChunk{
					BaseChunk: &bsr.BaseChunk{
						Protocol:  ssh.Protocol,
						Direction: bsr.Inbound,
						Timestamp: bsr.NewTimestamp(ts),
						Type:      bsr.ChunkHeader,
					},
					Compression: bsr.NoCompression,
					Encryption:  bsr.NoEncryption,
					SessionId:   "sess_123456789",
				},
				&bsr.EndChunk{
					BaseChunk: &bsr.BaseChunk{
						Protocol:  ssh.Protocol,
						Direction: bsr.Inbound,
						Timestamp: bsr.NewTimestamp(ts.Add(time.Second)),
						Type:      bsr.ChunkEnd,
					},
				},
			),
			newScanner(
				&bsr.HeaderChunk{
					BaseChunk: &bsr.BaseChunk{
						Protocol:  ssh.Protocol,
						Direction: bsr.Inbound,
						Timestamp: bsr.NewTimestamp(ts),
						Type:      bsr.ChunkHeader,
					},
					Compression: bsr.NoCompression,
					Encryption:  bsr.NoEncryption,
					SessionId:   "sess_123456789",
				},
				&ssh.DataChunk{
					BaseChunk: &bsr.BaseChunk{
						Protocol:  ssh.Protocol,
						Direction: bsr.Inbound,
						Timestamp: bsr.NewTimestamp(ts.Add(time.Microsecond)),
						Type:      ssh.DataChunkType,
					},
					Data: []byte("ls -lash"),
				},
				&bsr.EndChunk{
					BaseChunk: &bsr.BaseChunk{
						Protocol:  ssh.Protocol,
						Direction: bsr.Inbound,
						Timestamp: bsr.NewTimestamp(ts.Add(2 * time.Second)),
						Type:      bsr.ChunkEnd,
					},
				},
			),
			newW(),
			nil,
			[]byte(`{"version":2,"width":80,"height":24,"timestamp":1678963623,"env":{"SHELL":"/bin/bash","TERM":"xterm"}}
[0.000001,"o","ls -lash"]
`),
			nil,
		},
		{
			"no-pty-no-env-multiple-messages",
			newScanner(
				&bsr.HeaderChunk{
					BaseChunk: &bsr.BaseChunk{
						Protocol:  ssh.Protocol,
						Direction: bsr.Inbound,
						Timestamp: bsr.NewTimestamp(ts),
						Type:      bsr.ChunkHeader,
					},
					Compression: bsr.NoCompression,
					Encryption:  bsr.NoEncryption,
					SessionId:   "sess_123456789",
				},
				&bsr.EndChunk{
					BaseChunk: &bsr.BaseChunk{
						Protocol:  ssh.Protocol,
						Direction: bsr.Inbound,
						Timestamp: bsr.NewTimestamp(ts.Add(time.Second)),
						Type:      bsr.ChunkEnd,
					},
				},
			),
			newScanner(
				&bsr.HeaderChunk{
					BaseChunk: &bsr.BaseChunk{
						Protocol:  ssh.Protocol,
						Direction: bsr.Inbound,
						Timestamp: bsr.NewTimestamp(ts),
						Type:      bsr.ChunkHeader,
					},
					Compression: bsr.NoCompression,
					Encryption:  bsr.NoEncryption,
					SessionId:   "sess_123456789",
				},
				&ssh.DataChunk{
					BaseChunk: &bsr.BaseChunk{
						Protocol:  ssh.Protocol,
						Direction: bsr.Inbound,
						Timestamp: bsr.NewTimestamp(ts.Add(time.Microsecond)),
						Type:      ssh.DataChunkType,
					},
					Data: []byte("ls -lash"),
				},
				&ssh.DataChunk{
					BaseChunk: &bsr.BaseChunk{
						Protocol:  ssh.Protocol,
						Direction: bsr.Inbound,
						Timestamp: bsr.NewTimestamp(ts.Add(2 * time.Microsecond)),
						Type:      ssh.DataChunkType,
					},
					Data: []byte("foo\r\n"),
				},
				&bsr.EndChunk{
					BaseChunk: &bsr.BaseChunk{
						Protocol:  ssh.Protocol,
						Direction: bsr.Inbound,
						Timestamp: bsr.NewTimestamp(ts.Add(2 * time.Second)),
						Type:      bsr.ChunkEnd,
					},
				},
			),
			newW(),
			nil,
			[]byte(`{"version":2,"width":80,"height":24,"timestamp":1678963623,"env":{"SHELL":"/bin/bash","TERM":"xterm"}}
[0.000001,"o","ls -lash"]
[0.000002,"o","foo\r\n"]
`),
			nil,
		},
		{
			"nil-requestScanner",
			nil,
			newScanner(
				&bsr.HeaderChunk{
					BaseChunk: &bsr.BaseChunk{
						Protocol:  ssh.Protocol,
						Direction: bsr.Inbound,
						Timestamp: bsr.NewTimestamp(ts),
						Type:      bsr.ChunkHeader,
					},
					Compression: bsr.NoCompression,
					Encryption:  bsr.NoEncryption,
					SessionId:   "sess_123456789",
				},
				&bsr.EndChunk{
					BaseChunk: &bsr.BaseChunk{
						Protocol:  ssh.Protocol,
						Direction: bsr.Inbound,
						Timestamp: bsr.NewTimestamp(ts.Add(time.Second)),
						Type:      bsr.ChunkEnd,
					},
				},
			),
			newW(),
			nil,
			nil,
			errors.New("convert.sshChannelToAsciicast: missing request scanner: invalid parameter"),
		},
		{
			"nil-messageScanner",
			newScanner(
				&bsr.HeaderChunk{
					BaseChunk: &bsr.BaseChunk{
						Protocol:  ssh.Protocol,
						Direction: bsr.Inbound,
						Timestamp: bsr.NewTimestamp(ts),
						Type:      bsr.ChunkHeader,
					},
					Compression: bsr.NoCompression,
					Encryption:  bsr.NoEncryption,
					SessionId:   "sess_123456789",
				},
				&bsr.EndChunk{
					BaseChunk: &bsr.BaseChunk{
						Protocol:  ssh.Protocol,
						Direction: bsr.Inbound,
						Timestamp: bsr.NewTimestamp(ts.Add(time.Second)),
						Type:      bsr.ChunkEnd,
					},
				},
			),
			nil,
			newW(),
			nil,
			nil,
			errors.New("convert.sshChannelToAsciicast: missing message scanner: invalid parameter"),
		},
		{
			"nil-w",
			newScanner(
				&bsr.HeaderChunk{
					BaseChunk: &bsr.BaseChunk{
						Protocol:  ssh.Protocol,
						Direction: bsr.Inbound,
						Timestamp: bsr.NewTimestamp(ts),
						Type:      bsr.ChunkHeader,
					},
					Compression: bsr.NoCompression,
					Encryption:  bsr.NoEncryption,
					SessionId:   "sess_123456789",
				},
				&bsr.EndChunk{
					BaseChunk: &bsr.BaseChunk{
						Protocol:  ssh.Protocol,
						Direction: bsr.Inbound,
						Timestamp: bsr.NewTimestamp(ts.Add(time.Second)),
						Type:      bsr.ChunkEnd,
					},
				},
			),
			newScanner(
				&bsr.HeaderChunk{
					BaseChunk: &bsr.BaseChunk{
						Protocol:  ssh.Protocol,
						Direction: bsr.Inbound,
						Timestamp: bsr.NewTimestamp(ts),
						Type:      bsr.ChunkHeader,
					},
					Compression: bsr.NoCompression,
					Encryption:  bsr.NoEncryption,
					SessionId:   "sess_123456789",
				},
				&bsr.EndChunk{
					BaseChunk: &bsr.BaseChunk{
						Protocol:  ssh.Protocol,
						Direction: bsr.Inbound,
						Timestamp: bsr.NewTimestamp(ts.Add(time.Second)),
						Type:      bsr.ChunkEnd,
					},
				},
			),
			nil,
			nil,
			nil,
			errors.New("convert.sshChannelToAsciicast: missing read write seeker: invalid parameter"),
		},
		{
			"data-before-header",
			newScanner(
				&bsr.HeaderChunk{
					BaseChunk: &bsr.BaseChunk{
						Protocol:  ssh.Protocol,
						Direction: bsr.Inbound,
						Timestamp: bsr.NewTimestamp(ts),
						Type:      bsr.ChunkHeader,
					},
					Compression: bsr.NoCompression,
					Encryption:  bsr.NoEncryption,
					SessionId:   "sess_123456789",
				},
				&bsr.EndChunk{
					BaseChunk: &bsr.BaseChunk{
						Protocol:  ssh.Protocol,
						Direction: bsr.Inbound,
						Timestamp: bsr.NewTimestamp(ts.Add(time.Second)),
						Type:      bsr.ChunkEnd,
					},
				},
			),
			newScanner(
				&ssh.DataChunk{
					BaseChunk: &bsr.BaseChunk{
						Protocol:  ssh.Protocol,
						Direction: bsr.Inbound,
						Timestamp: bsr.NewTimestamp(ts.Add(time.Microsecond)),
						Type:      ssh.DataChunkType,
					},
					Data: []byte("ls -lash"),
				},
				&bsr.EndChunk{
					BaseChunk: &bsr.BaseChunk{
						Protocol:  ssh.Protocol,
						Direction: bsr.Inbound,
						Timestamp: bsr.NewTimestamp(ts.Add(2 * time.Second)),
						Type:      bsr.ChunkEnd,
					},
				},
			),
			newW(),
			nil,
			nil,
			errors.New("convert.sshChannelToAsciicast: bsr.ChunkWalk: data chunk before header: malformed bsr data file"),
		},
		{
			"multiple-header",
			newScanner(
				&bsr.HeaderChunk{
					BaseChunk: &bsr.BaseChunk{
						Protocol:  ssh.Protocol,
						Direction: bsr.Inbound,
						Timestamp: bsr.NewTimestamp(ts),
						Type:      bsr.ChunkHeader,
					},
					Compression: bsr.NoCompression,
					Encryption:  bsr.NoEncryption,
					SessionId:   "sess_123456789",
				},
				&bsr.EndChunk{
					BaseChunk: &bsr.BaseChunk{
						Protocol:  ssh.Protocol,
						Direction: bsr.Inbound,
						Timestamp: bsr.NewTimestamp(ts.Add(time.Second)),
						Type:      bsr.ChunkEnd,
					},
				},
			),
			newScanner(
				&bsr.HeaderChunk{
					BaseChunk: &bsr.BaseChunk{
						Protocol:  ssh.Protocol,
						Direction: bsr.Inbound,
						Timestamp: bsr.NewTimestamp(ts),
						Type:      bsr.ChunkHeader,
					},
					Compression: bsr.NoCompression,
					Encryption:  bsr.NoEncryption,
					SessionId:   "sess_123456789",
				},
				&bsr.HeaderChunk{
					BaseChunk: &bsr.BaseChunk{
						Protocol:  ssh.Protocol,
						Direction: bsr.Inbound,
						Timestamp: bsr.NewTimestamp(ts),
						Type:      bsr.ChunkHeader,
					},
					Compression: bsr.NoCompression,
					Encryption:  bsr.NoEncryption,
					SessionId:   "sess_123456789",
				},
				&bsr.EndChunk{
					BaseChunk: &bsr.BaseChunk{
						Protocol:  ssh.Protocol,
						Direction: bsr.Inbound,
						Timestamp: bsr.NewTimestamp(ts.Add(time.Second)),
						Type:      bsr.ChunkEnd,
					},
				},
			),
			newW(),
			nil,
			nil,
			errors.New("convert.sshChannelToAsciicast: bsr.ChunkWalk: multiple header chunks: malformed bsr data file"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, err := sshChannelToAsciicast(
				ctx,
				tc.requestScanner,
				tc.messageScanner,
				tc.w,
				tc.opts...,
			)
			if tc.wantErr != nil {
				require.EqualError(t, err, tc.wantErr.Error())
				return
			}
			require.NoError(t, err)
			got, err := io.ReadAll(r)
			require.NoError(t, err)
			require.Equal(t, string(tc.want), string(got))

			err = r.Close()
			require.NoError(t, err)
		})
	}
}
