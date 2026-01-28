// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package ssh

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/bsr"
	pssh "github.com/hashicorp/boundary/internal/bsr/gen/ssh/v1"
	"github.com/stretchr/testify/require"
	gssh "golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/proto"
)

func Test_NewPtyRequest(t *testing.T) {
	ctx := context.Background()
	now := bsr.NewTimestamp(time.Now())

	// emulate how go ssh encodes the termmode
	termmodes := gssh.TerminalModes{
		gssh.ECHO:          0,
		gssh.TTY_OP_ISPEED: 14400,
		gssh.TTY_OP_OSPEED: 14400,
	}

	var tm []byte
	for k, v := range termmodes {
		kv := struct {
			Key byte
			Val uint32
		}{k, v}

		tm = append(tm, gssh.Marshal(&kv)...)
	}
	tm = append(tm, 0)

	message := ptySigval{
		TermEnvVar:              "var",
		TerminalWidthCharacters: 123,
		TerminalHeightRows:      456,
		TerminalWidthPixels:     789,
		TerminalHeightPixels:    234,
		EncodedTerminalMode:     tm,
	}
	payload := gssh.Marshal(message)

	tests := []struct {
		name      string
		direction bsr.Direction
		time      *bsr.Timestamp
		request   *gssh.Request
		expErr    bool
		expErrMsg string
	}{
		{
			name:      "nil request",
			direction: bsr.Inbound,
			time:      now,
			expErr:    true,
			expErrMsg: "ssh.NewPtyRequest: request cannot be nil: invalid parameter",
		},
		{
			name: "empty direction",
			time: now,
			request: &gssh.Request{
				Type:      PtyRequestType,
				WantReply: false,
				Payload:   payload,
			},
			expErr:    true,
			expErrMsg: "ssh.NewPtyRequest: invalid direction: invalid parameter",
		},
		{
			name:      "empty time",
			direction: bsr.Inbound,
			request: &gssh.Request{
				Type:      PtyRequestType,
				WantReply: false,
				Payload:   payload,
			},
			expErr:    true,
			expErrMsg: "ssh.NewPtyRequest: timestamp cannot be nil: invalid parameter",
		},
		{
			name:      "bad type",
			direction: bsr.Inbound,
			time:      now,
			request: &gssh.Request{
				Type:      "muahaha",
				WantReply: false,
				Payload:   payload,
			},
			expErr:    true,
			expErrMsg: `ssh.NewPtyRequest: request type must be "pty-req": invalid parameter`,
		},
		{
			name:      "happy path",
			direction: bsr.Inbound,
			time:      now,
			request: &gssh.Request{
				Type:      PtyRequestType,
				WantReply: false,
				Payload:   payload,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rc, err := NewPtyRequest(ctx, tt.direction, tt.time, tt.request)
			if tt.expErr {
				require.EqualError(t, err, tt.expErrMsg)
				require.Nil(t, rc)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, rc)

			data, err := rc.MarshalData(ctx)
			require.NoError(t, err)
			dataPayload := &pssh.PtyRequest{}
			err = proto.Unmarshal(data, dataPayload)
			require.NoError(t, err)
			require.Equal(t, dataPayload.TermEnvVar, message.TermEnvVar)
			require.Equal(t, dataPayload.TerminalWidthCharacters, message.TerminalWidthCharacters)
			require.Equal(t, dataPayload.TerminalHeightRows, message.TerminalHeightRows)
			require.Equal(t, dataPayload.TerminalWidthPixels, message.TerminalWidthPixels)
			require.Equal(t, dataPayload.TerminalHeightPixels, message.TerminalHeightPixels)
			require.Equal(t, dataPayload.EncodedTerminalMode, message.EncodedTerminalMode)
			require.Equal(t, dataPayload.RequestType, PtyRequestType)
			require.Equal(t, dataPayload.WantReply, false)
		})
	}
}
