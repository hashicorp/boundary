// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package session

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConnectWith_validate(t *testing.T) {
	ctx := context.Background()
	id, err := newId(ctx)
	require.NoError(t, err)

	type fields struct {
		SessionId          string
		ClientTcpAddress   string
		ClientTcpPort      uint32
		EndpointTcpAddress string
		EndpointTcpPort    uint32
		UserClientIp       string
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "valid-ipv4",
			fields: fields{
				SessionId:          id,
				ClientTcpAddress:   "0.0.0.1",
				ClientTcpPort:      22,
				EndpointTcpAddress: "0.0.0.1",
				EndpointTcpPort:    2222,
				UserClientIp:       "127.0.0.1",
			},
		},
		{
			name: "valid-ipv6",
			fields: fields{
				SessionId:          id,
				ClientTcpAddress:   "::1",
				ClientTcpPort:      22,
				EndpointTcpAddress: "::1",
				EndpointTcpPort:    2222,
				UserClientIp:       "::2",
			},
		},
		{
			name: "missing-SessionId",
			fields: fields{
				ClientTcpAddress:   "0.0.0.1",
				ClientTcpPort:      22,
				EndpointTcpAddress: "0.0.0.1",
				EndpointTcpPort:    2222,
			},
			wantErr: true,
		},
		{
			name: "missing-ClientTcpAddress",
			fields: fields{
				SessionId:          id,
				ClientTcpPort:      22,
				EndpointTcpAddress: "0.0.0.1",
				EndpointTcpPort:    2222,
			},
			wantErr: true,
		},
		{
			name: "missing-ClientTcpPort",
			fields: fields{
				SessionId:          id,
				ClientTcpAddress:   "0.0.0.1",
				EndpointTcpAddress: "0.0.0.1",
				EndpointTcpPort:    2222,
			},
			wantErr: true,
		},
		{
			name: "missing-EndpointTcpAddress",
			fields: fields{
				SessionId:        id,
				ClientTcpAddress: "0.0.0.1",
				ClientTcpPort:    22,
				EndpointTcpPort:  2222,
			},
			wantErr: true,
		},
		{
			name: "missing-EndpointTcpPort",
			fields: fields{
				SessionId:          id,
				ClientTcpAddress:   "0.0.0.1",
				ClientTcpPort:      22,
				EndpointTcpAddress: "0.0.0.1",
			},
			wantErr: true,
		},
		{
			name: "missing-UserClientIp",
			fields: fields{
				SessionId:          id,
				ClientTcpAddress:   "0.0.0.1",
				ClientTcpPort:      22,
				EndpointTcpAddress: "0.0.0.1",
				EndpointTcpPort:    2222,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := ConnectWith{
				ConnectionId:       tt.fields.SessionId,
				ClientTcpAddress:   tt.fields.ClientTcpAddress,
				ClientTcpPort:      tt.fields.ClientTcpPort,
				EndpointTcpAddress: tt.fields.EndpointTcpAddress,
				EndpointTcpPort:    tt.fields.EndpointTcpPort,
				UserClientIp:       tt.fields.UserClientIp,
			}
			if err := c.validate(ctx); (err != nil) != tt.wantErr {
				t.Errorf("ConnectWith.validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
