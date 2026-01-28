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

func Test_NewBreakRequest(t *testing.T) {
	ctx := context.Background()
	now := bsr.NewTimestamp(time.Now())
	message := breakSigval{BreakLengthMs: 123}
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
			expErrMsg: "ssh.NewBreakRequest: request cannot be nil: invalid parameter",
		},
		{
			name: "empty direction",
			time: now,
			request: &gssh.Request{
				Type:      BreakRequestType,
				WantReply: false,
				Payload:   payload,
			},
			expErr:    true,
			expErrMsg: "ssh.NewBreakRequest: invalid direction: invalid parameter",
		},
		{
			name:      "empty time",
			direction: bsr.Inbound,
			request: &gssh.Request{
				Type:      BreakRequestType,
				WantReply: false,
				Payload:   payload,
			},
			expErr:    true,
			expErrMsg: "ssh.NewBreakRequest: timestamp cannot be nil: invalid parameter",
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
			expErrMsg: `ssh.NewBreakRequest: request type must be "break": invalid parameter`,
		},
		{
			name:      "happy path",
			direction: bsr.Inbound,
			time:      now,
			request: &gssh.Request{
				Type:      BreakRequestType,
				WantReply: false,
				Payload:   payload,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rc, err := NewBreakRequest(ctx, tt.direction, tt.time, tt.request)
			if tt.expErr {
				require.EqualError(t, err, tt.expErrMsg)
				require.Nil(t, rc)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, rc)

			data, err := rc.MarshalData(ctx)
			require.NoError(t, err)
			dataPayload := &pssh.BreakRequest{}
			err = proto.Unmarshal(data, dataPayload)
			require.NoError(t, err)
			require.Equal(t, dataPayload.BreakLengthMs, message.BreakLengthMs)
			require.Equal(t, dataPayload.RequestType, BreakRequestType)
			require.Equal(t, dataPayload.WantReply, false)
		})
	}
}
