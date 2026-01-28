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

func Test_NewForwardedTCPIPRequest(t *testing.T) {
	ctx := context.Background()
	now := bsr.NewTimestamp(time.Now())
	message := forwardedTCPIPRequestSigval{
		SenderChannel:       123,
		InitialWindowSize:   456,
		MaximumPacketSize:   789,
		Address:             "addy",
		Port:                99,
		OriginatorIpAddress: "original addy",
		OriginatorPort:      22,
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
			expErrMsg: "ssh.NewForwardedTCPIPRequest: request cannot be nil: invalid parameter",
		},
		{
			name: "empty direction",
			time: now,
			request: &gssh.Request{
				Type:      ForwardedTCPIPRequestType,
				WantReply: false,
				Payload:   payload,
			},
			expErr:    true,
			expErrMsg: "ssh.NewForwardedTCPIPRequest: invalid direction: invalid parameter",
		},
		{
			name:      "empty time",
			direction: bsr.Inbound,
			request: &gssh.Request{
				Type:      ForwardedTCPIPRequestType,
				WantReply: false,
				Payload:   payload,
			},
			expErr:    true,
			expErrMsg: "ssh.NewForwardedTCPIPRequest: timestamp cannot be nil: invalid parameter",
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
			expErrMsg: `ssh.NewForwardedTCPIPRequest: request type must be "forwarded-tcpip": invalid parameter`,
		},
		{
			name:      "happy path",
			direction: bsr.Inbound,
			time:      now,
			request: &gssh.Request{
				Type:      ForwardedTCPIPRequestType,
				WantReply: false,
				Payload:   payload,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rc, err := NewForwardedTCPIPRequest(ctx, tt.direction, tt.time, tt.request)
			if tt.expErr {
				require.EqualError(t, err, tt.expErrMsg)
				require.Nil(t, rc)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, rc)

			data, err := rc.MarshalData(ctx)
			require.NoError(t, err)
			dataPayload := &pssh.ForwardedTCPIPRequest{}
			err = proto.Unmarshal(data, dataPayload)
			require.NoError(t, err)
			require.Equal(t, dataPayload.SenderChannel, message.SenderChannel)
			require.Equal(t, dataPayload.InitialWindowSize, message.InitialWindowSize)
			require.Equal(t, dataPayload.MaximumPacketSize, message.MaximumPacketSize)
			require.Equal(t, dataPayload.Address, message.Address)
			require.Equal(t, dataPayload.Port, message.Port)
			require.Equal(t, dataPayload.OriginatorPort, message.OriginatorPort)
			require.Equal(t, dataPayload.OriginatorIpAddress, message.OriginatorIpAddress)
			require.Equal(t, dataPayload.RequestType, ForwardedTCPIPRequestType)
		})
	}
}
