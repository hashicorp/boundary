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

func Test_NewEnvRequest(t *testing.T) {
	ctx := context.Background()
	now := bsr.NewTimestamp(time.Now())
	message := envSigval{Name: "my baloney has a first name", Value: "it's h-o-m-e-r"}
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
			expErrMsg: "ssh.NewEnvRequest: request cannot be nil: invalid parameter",
		},
		{
			name: "empty direction",
			time: now,
			request: &gssh.Request{
				Type:      EnvRequestType,
				WantReply: false,
				Payload:   payload,
			},
			expErr:    true,
			expErrMsg: "ssh.NewEnvRequest: invalid direction: invalid parameter",
		},
		{
			name:      "empty time",
			direction: bsr.Inbound,
			request: &gssh.Request{
				Type:      EnvRequestType,
				WantReply: false,
				Payload:   payload,
			},
			expErr:    true,
			expErrMsg: "ssh.NewEnvRequest: timestamp cannot be nil: invalid parameter",
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
			expErrMsg: `ssh.NewEnvRequest: request type must be "env": invalid parameter`,
		},
		{
			name:      "happy path",
			direction: bsr.Inbound,
			time:      now,
			request: &gssh.Request{
				Type:      EnvRequestType,
				WantReply: false,
				Payload:   payload,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rc, err := NewEnvRequest(ctx, tt.direction, tt.time, tt.request)
			if tt.expErr {
				require.EqualError(t, err, tt.expErrMsg)
				require.Nil(t, rc)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, rc)

			data, err := rc.MarshalData(ctx)
			require.NoError(t, err)
			dataPayload := &pssh.EnvRequest{}
			err = proto.Unmarshal(data, dataPayload)
			require.NoError(t, err)
			require.Equal(t, dataPayload.VariableName, message.Name)
			require.Equal(t, dataPayload.VariableValue, message.Value)
			require.Equal(t, dataPayload.RequestType, EnvRequestType)
			require.Equal(t, dataPayload.WantReply, false)
		})
	}
}
