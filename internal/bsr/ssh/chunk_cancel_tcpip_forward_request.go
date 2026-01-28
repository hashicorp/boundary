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

const CancelTCPIPForwardRequestType = "cancel-tcpip-forward"

// CancelTCPIPForwardRequest is a chunk to contain data for an SSH Cancel TCIPIP Forward request
type CancelTCPIPForwardRequest struct {
	*bsr.BaseChunk
	*pssh.CancelTCPIPForwardRequest
}

// MarshalData serializes a CancelTCPIPForwardRequest chunk
func (r *CancelTCPIPForwardRequest) MarshalData(ctx context.Context) ([]byte, error) {
	const op = "ssh.(CancelTCPIPForwardRequest).MarshalData"
	dataBytes, err := proto.Marshal(r.CancelTCPIPForwardRequest)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to marshal data: %w", op, err)
	}

	d := make([]byte, 0, len(dataBytes))
	d = append(d, dataBytes...)

	return d, nil
}

// NewCancelTCPIPForwardRequest creates a CancelTCPIPForwardRequest chunk
func NewCancelTCPIPForwardRequest(ctx context.Context, d bsr.Direction, t *bsr.Timestamp, r *gssh.Request) (*CancelTCPIPForwardRequest, error) {
	const op = "ssh.NewCancelTCPIPForwardRequest"

	if is.Nil(r) {
		return nil, fmt.Errorf("%s: request cannot be nil: %w", op, bsr.ErrInvalidParameter)
	}
	if r.Type != CancelTCPIPForwardRequestType {
		return nil, fmt.Errorf("%s: request type must be %q: %w", op, CancelTCPIPForwardRequestType, bsr.ErrInvalidParameter)
	}
	if !bsr.ValidDirection(d) {
		return nil, fmt.Errorf("%s: invalid direction: %w", op, bsr.ErrInvalidParameter)
	}
	if is.Nil(t) {
		return nil, fmt.Errorf("%s: timestamp cannot be nil: %w", op, bsr.ErrInvalidParameter)
	}

	baseChunk, err := bsr.NewBaseChunk(ctx, Protocol, d, t, CancelTCPIPForwardReqChunkType)
	if err != nil {
		return nil, fmt.Errorf("%s: unable to create base chunk: %w", op, err)
	}

	var sigval cancelTCPIPForwardSigval
	if err := gssh.Unmarshal(r.Payload, &sigval); err != nil {
		return nil, fmt.Errorf("%s: unable to unmarshal payload: %w", op, err)
	}
	reqData := &CancelTCPIPForwardRequest{
		BaseChunk: baseChunk,
		CancelTCPIPForwardRequest: &pssh.CancelTCPIPForwardRequest{
			RequestType:   r.Type,
			WantReply:     r.WantReply,
			AddressToBind: sigval.AddressToBind,
			PortToBind:    sigval.PortToBind,
		},
	}
	return reqData, nil
}

type cancelTCPIPForwardSigval struct {
	AddressToBind string
	PortToBind    uint32
}
