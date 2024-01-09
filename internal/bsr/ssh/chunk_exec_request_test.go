// Copyright (c) HashiCorp, Inc.
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

func Test_NewExecRequest(t *testing.T) {
	ctx := context.Background()
	now := bsr.NewTimestamp(time.Now())
	message := execSigval{Command: "recycle!"}
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
			expErrMsg: "ssh.NewExecRequest: request cannot be nil: invalid parameter",
		},
		{
			name: "empty direction",
			time: now,
			request: &gssh.Request{
				Type:      ExecRequestType,
				WantReply: false,
				Payload:   payload,
			},
			expErr:    true,
			expErrMsg: "ssh.NewExecRequest: invalid direction: invalid parameter",
		},
		{
			name:      "empty time",
			direction: bsr.Inbound,
			request: &gssh.Request{
				Type:      ExecRequestType,
				WantReply: false,
				Payload:   payload,
			},
			expErr:    true,
			expErrMsg: "ssh.NewExecRequest: timestamp cannot be nil: invalid parameter",
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
			expErrMsg: `ssh.NewExecRequest: request type must be "exec": invalid parameter`,
		},
		{
			name:      "happy path",
			direction: bsr.Inbound,
			time:      now,
			request: &gssh.Request{
				Type:      ExecRequestType,
				WantReply: false,
				Payload:   payload,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rc, err := NewExecRequest(ctx, tt.direction, tt.time, tt.request)
			if tt.expErr {
				require.EqualError(t, err, tt.expErrMsg)
				require.Nil(t, rc)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, rc)

			data, err := rc.MarshalData(ctx)
			require.NoError(t, err)
			dataPayload := &pssh.ExecRequest{}
			err = proto.Unmarshal(data, dataPayload)
			require.NoError(t, err)
			require.Equal(t, dataPayload.Command, message.Command)
			require.Equal(t, dataPayload.RequestType, ExecRequestType)
			require.Equal(t, dataPayload.WantReply, false)
		})
	}
}
