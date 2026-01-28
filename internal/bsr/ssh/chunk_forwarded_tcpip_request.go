// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package ssh

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/bsr"
	pssh "github.com/hashicorp/boundary/internal/bsr/gen/ssh/v1"
	"github.com/hashicorp/boundary/internal/bsr/internal/is"
	gssh "golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/proto"
)

const ForwardedTCPIPRequestType = "forwarded-tcpip"

// ForwardedTCPIPRequest is a chunk to contain data for an SSH Forwarded TCPIP request
type ForwardedTCPIPRequest struct {
	*bsr.BaseChunk
	*pssh.ForwardedTCPIPRequest
}

// MarshalData serializes an ForwardedTCPIPRequest chunk
func (r *ForwardedTCPIPRequest) MarshalData(ctx context.Context) ([]byte, error) {
	const op = "ssh.(ForwardedTCPIPRequest).MarshalData"
	dataBytes, err := proto.Marshal(r.ForwardedTCPIPRequest)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to marshal data: %w", op, err)
	}

	d := make([]byte, 0, len(dataBytes))
	d = append(d, dataBytes...)

	return d, nil
}

// NewForwardedTCPIPRequest creates an ForwardedTCPIPRequest chunk
func NewForwardedTCPIPRequest(ctx context.Context, d bsr.Direction, t *bsr.Timestamp, r *gssh.Request) (*ForwardedTCPIPRequest, error) {
	const op = "ssh.NewForwardedTCPIPRequest"

	if is.Nil(r) {
		return nil, fmt.Errorf("%s: request cannot be nil: %w", op, bsr.ErrInvalidParameter)
	}
	if r.Type != ForwardedTCPIPRequestType {
		return nil, fmt.Errorf("%s: request type must be %q: %w", op, ForwardedTCPIPRequestType, bsr.ErrInvalidParameter)
	}
	if !bsr.ValidDirection(d) {
		return nil, fmt.Errorf("%s: invalid direction: %w", op, bsr.ErrInvalidParameter)
	}
	if is.Nil(t) {
		return nil, fmt.Errorf("%s: timestamp cannot be nil: %w", op, bsr.ErrInvalidParameter)
	}

	baseChunk, err := bsr.NewBaseChunk(ctx, Protocol, d, t, ForwardedTCPIPReqChunkType)
	if err != nil {
		return nil, fmt.Errorf("%s: unable to create base chunk: %w", op, err)
	}

	var sigval forwardedTCPIPRequestSigval
	if err := gssh.Unmarshal(r.Payload, &sigval); err != nil {
		return nil, fmt.Errorf("%s: unable to unmarshal payload: %w", op, err)
	}
	reqData := &ForwardedTCPIPRequest{
		BaseChunk: baseChunk,
		ForwardedTCPIPRequest: &pssh.ForwardedTCPIPRequest{
			RequestType:         r.Type,
			SenderChannel:       sigval.SenderChannel,
			InitialWindowSize:   sigval.InitialWindowSize,
			MaximumPacketSize:   sigval.MaximumPacketSize,
			Address:             sigval.Address,
			Port:                sigval.Port,
			OriginatorIpAddress: sigval.OriginatorIpAddress,
			OriginatorPort:      sigval.OriginatorPort,
		},
	}
	return reqData, nil
}

type forwardedTCPIPRequestSigval struct {
	SenderChannel       uint32
	InitialWindowSize   uint32
	MaximumPacketSize   uint32
	Address             string
	Port                uint32
	OriginatorIpAddress string
	OriginatorPort      uint32
}
