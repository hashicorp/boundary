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

const SubsystemRequestType = "subsystem"

// SubsystemRequest is a chunk to contain data for an SSH Subsystem request
type SubsystemRequest struct {
	*bsr.BaseChunk
	*pssh.SubsystemRequest
}

// MarshalData serializes an SubsystemRequest chunk
func (r *SubsystemRequest) MarshalData(ctx context.Context) ([]byte, error) {
	const op = "ssh.(SubsystemRequest).MarshalData"
	dataBytes, err := proto.Marshal(r.SubsystemRequest)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to marshal data: %w", op, err)
	}

	d := make([]byte, 0, len(dataBytes))
	d = append(d, dataBytes...)

	return d, nil
}

// NewSubsystemRequest creates an SubsystemRequest chunk
func NewSubsystemRequest(ctx context.Context, d bsr.Direction, t *bsr.Timestamp, r *gssh.Request) (*SubsystemRequest, error) {
	const op = "ssh.NewSubsystemRequest"

	if is.Nil(r) {
		return nil, fmt.Errorf("%s: request cannot be nil: %w", op, bsr.ErrInvalidParameter)
	}
	if r.Type != SubsystemRequestType {
		return nil, fmt.Errorf("%s: request type must be %q: %w", op, SubsystemRequestType, bsr.ErrInvalidParameter)
	}
	if !bsr.ValidDirection(d) {
		return nil, fmt.Errorf("%s: invalid direction: %w", op, bsr.ErrInvalidParameter)
	}
	if is.Nil(t) {
		return nil, fmt.Errorf("%s: timestamp cannot be nil: %w", op, bsr.ErrInvalidParameter)
	}

	baseChunk, err := bsr.NewBaseChunk(ctx, Protocol, d, t, SubsystemReqChunkType)
	if err != nil {
		return nil, fmt.Errorf("%s: unable to create base chunk: %w", op, err)
	}

	var sigval subsystemSigval
	if err := gssh.Unmarshal(r.Payload, &sigval); err != nil {
		return nil, fmt.Errorf("%s: unable to unmarshal payload: %w", op, err)
	}
	reqData := &SubsystemRequest{
		BaseChunk: baseChunk,
		SubsystemRequest: &pssh.SubsystemRequest{
			RequestType:   r.Type,
			WantReply:     r.WantReply,
			SubsystemName: sigval.SubsystemName,
		},
	}
	return reqData, nil
}

type subsystemSigval struct {
	SubsystemName string
}
