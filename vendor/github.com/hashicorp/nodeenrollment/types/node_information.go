// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package types

import (
	"context"
	"fmt"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/nodeenrollment"
	"google.golang.org/protobuf/proto"
)

var _ nodeenrollment.X25519KeyProducer = (*NodeInformation)(nil)

// Store stores node information to server storage, wrapping values along the
// way if given a wrapper
//
// Supported options: WithStorageWrapper
func (n *NodeInformation) Store(ctx context.Context, storage nodeenrollment.Storage, opt ...nodeenrollment.Option) error {
	const op = "nodeenrollment.types.(NodeInformation).Store"

	switch {
	case nodeenrollment.IsNil(storage):
		return fmt.Errorf("(%s) storage is nil", op)

	case nodeenrollment.IsNil(n):
		return fmt.Errorf("(%s) node information is nil", op)

	case n.Id == "":
		return fmt.Errorf("(%s) node is missing id", op)
	}
	opts, err := nodeenrollment.GetOpts(opt...)
	if err != nil {
		return fmt.Errorf("(%s) error parsing options: %w", op, err)
	}

	infoToStore := proto.Clone(n).(*NodeInformation)
	if opts.WithStorageWrapper != nil {
		keyId, err := opts.WithStorageWrapper.KeyId(ctx)
		if err != nil {
			return fmt.Errorf("(%s) error reading wrapper key id: %w", op, err)
		}
		infoToStore.WrappingKeyId = keyId

		if len(infoToStore.ServerEncryptionPrivateKeyBytes) > 0 {
			blobInfo, err := opts.WithStorageWrapper.Encrypt(
				ctx,
				infoToStore.ServerEncryptionPrivateKeyBytes,
				wrapping.WithAad(infoToStore.CertificatePublicKeyPkix),
			)
			if err != nil {
				return fmt.Errorf("(%s) error wrapping private key: %w", op, err)
			}
			infoToStore.ServerEncryptionPrivateKeyBytes, err = proto.Marshal(blobInfo)
			if err != nil {
				return fmt.Errorf("(%s) error marshaling wrapped private key: %w", op, err)
			}
		}
	}

	if err := storage.Store(ctx, infoToStore); err != nil {
		return fmt.Errorf("(%s) error storing node information: %w", op, err)
	}

	return nil
}

// LoadNodeInformation loads the node information from storage, unwrapping encrypted
// values if needed.
//
// Supported options: WithStorageWrapper, WithState
func LoadNodeInformation(ctx context.Context, storage nodeenrollment.Storage, id string, opt ...nodeenrollment.Option) (*NodeInformation, error) {
	const op = "nodeenrollment.types.LoadNodeInformation"

	switch {
	case nodeenrollment.IsNil(storage):
		return nil, fmt.Errorf("(%s) storage is nil", op)
	case id == "":
		return nil, fmt.Errorf("(%s) missing id", op)
	}

	opts, err := nodeenrollment.GetOpts(opt...)
	if err != nil {
		return nil, fmt.Errorf("(%s) error parsing options: %w", op, err)
	}

	nodeInfo := &NodeInformation{
		Id:    id,
		State: opts.WithState,
	}
	if err := storage.Load(ctx, nodeInfo); err != nil {
		return nil, fmt.Errorf("(%s) error loading node information from storage: %w", op, err)
	}

	return decryptForLoad(ctx, nodeInfo, opt...)
}

// LoadNodeInformationSetByNodeId loads node information entries from storage by node id, unwrapping encrypted
// values if needed.
//
// Supported options: WithStorageWrapper
func LoadNodeInformationSetByNodeId(ctx context.Context, storage nodeenrollment.NodeIdLoader, nodeid string, opt ...nodeenrollment.Option) (*NodeInformationSet, error) {
	const op = "nodeenrollment.types.LoadNodeInformationSetByNodeId"

	switch {
	case nodeenrollment.IsNil(storage):
		return nil, fmt.Errorf("(%s) storage is nil", op)
	case nodeid == "":
		return nil, fmt.Errorf("(%s) missing node id", op)
	}

	nodeInfo := &NodeInformationSet{
		NodeId: nodeid,
	}
	if err := storage.LoadByNodeId(ctx, nodeInfo); err != nil {
		return nil, fmt.Errorf("(%s) error loading node information from storage: %w", op, err)
	}

	nodeInfosToReturn := make([]*NodeInformation, 0)
	for _, n := range nodeInfo.Nodes {
		n, err := decryptForLoad(ctx, n, opt...)
		if err != nil {
			return nil, err
		}
		thisNode := proto.Clone(n).(*NodeInformation)
		nodeInfosToReturn = append(nodeInfosToReturn, thisNode)
	}

	nodeInfos := &NodeInformationSet{
		NodeId: nodeid,
		Nodes:  nodeInfosToReturn,
	}
	return nodeInfos, nil
}

func decryptForLoad(ctx context.Context, nodeInfo *NodeInformation, opt ...nodeenrollment.Option) (*NodeInformation, error) {
	const op = "nodeenrollment.types.decryptForLoad"
	opts, err := nodeenrollment.GetOpts(opt...)
	if err != nil {
		return nil, fmt.Errorf("(%s) error parsing options: %w", op, err)
	}

	switch {
	case opts.WithStorageWrapper == nil && nodeInfo.WrappingKeyId != "":
		return nil, fmt.Errorf("(%s) node information has encrypted parts with wrapper key id %q but wrapper not provided", op, nodeInfo.WrappingKeyId)
	case nodeInfo.WrappingKeyId != "":
		// Note: not checking the wrapper key IDs against each other because if
		// using something like a PooledWrapper then the current encrypting ID
		// may not match, or if the wrapper performs its own internal key
		// selection.
		if len(nodeInfo.ServerEncryptionPrivateKeyBytes) > 0 {
			blobInfo := new(wrapping.BlobInfo)
			if err := proto.Unmarshal(nodeInfo.ServerEncryptionPrivateKeyBytes, blobInfo); err != nil {
				return nil, fmt.Errorf("(%s) error unmarshaling private key blob info: %w", op, err)
			}
			pt, err := opts.WithStorageWrapper.Decrypt(ctx, blobInfo, wrapping.WithAad(nodeInfo.CertificatePublicKeyPkix))
			if err != nil {
				return nil, fmt.Errorf("(%s) error decrypting private key: %w", op, err)
			}
			nodeInfo.ServerEncryptionPrivateKeyBytes = pt
		}

		nodeInfo.WrappingKeyId = ""
	}

	return nodeInfo, nil
}

// SetPreviousEncryptionKey will set this NodeInformation's PreviousEncryptionKey field
// using the passed NodeInformation
func (n *NodeInformation) SetPreviousEncryptionKey(oldNodeInformation *NodeInformation) error {
	const op = "nodeenrollment.types.(NodeInformation).SetPreviousEncryptionKey"
	if oldNodeInformation == nil {
		return fmt.Errorf("(%s) empty prior node information passed in", op)
	}

	keyId, err := nodeenrollment.KeyIdFromPkix(oldNodeInformation.CertificatePublicKeyPkix)
	if err != nil {
		return fmt.Errorf("(%s) error deriving key id: %w", op, err)
	}

	previousEncryptionKey := &EncryptionKey{
		KeyId:           keyId,
		PrivateKeyPkcs8: oldNodeInformation.ServerEncryptionPrivateKeyBytes,
		PrivateKeyType:  oldNodeInformation.ServerEncryptionPrivateKeyType,
		PublicKeyPkix:   oldNodeInformation.EncryptionPublicKeyBytes,
		PublicKeyType:   oldNodeInformation.EncryptionPublicKeyType,
	}
	n.PreviousEncryptionKey = previousEncryptionKey

	return nil
}

// X25519EncryptionKey uses the NodeInformation's values to produce a shared
// encryption key via X25519
func (n *NodeInformation) X25519EncryptionKey() (string, []byte, error) {
	const op = "nodeenrollment.types.(NodeInformation).X25519EncryptionKey"

	if nodeenrollment.IsNil(n) {
		return "", nil, fmt.Errorf("(%s) node information is empty", op)
	}

	out, err := X25519EncryptionKey(n.ServerEncryptionPrivateKeyBytes, n.ServerEncryptionPrivateKeyType, n.EncryptionPublicKeyBytes, n.EncryptionPublicKeyType)
	if err != nil {
		return "", nil, fmt.Errorf("(%s) error deriving encryption key: %w", op, err)
	}

	keyId, err := nodeenrollment.KeyIdFromPkix(n.CertificatePublicKeyPkix)
	if err != nil {
		return "", nil, fmt.Errorf("(%s) error deriving key id: %w", op, err)
	}

	return keyId, out, nil
}

// PreviousX25519EncryptionKey satisfies the X25519Producer and will produce a shared
// encryption key via X25519 if previous key data is present
func (n *NodeInformation) PreviousX25519EncryptionKey() (string, []byte, error) {
	const op = "nodeenrollment.types.(NodeInformation).PreviousX25519EncryptionKey"

	if nodeenrollment.IsNil(n) {
		return "", nil, fmt.Errorf("(%s) node information is empty", op)
	}

	previousKey := n.PreviousEncryptionKey
	if previousKey == nil {
		return "", nil, fmt.Errorf("(%s) previous key is empty", op)
	}

	out, err := X25519EncryptionKey(previousKey.PrivateKeyPkcs8, previousKey.PrivateKeyType, previousKey.PublicKeyPkix, previousKey.PublicKeyType)
	if err != nil {
		return "", nil, fmt.Errorf("(%s) error deriving previous encryption key: %w", op, err)
	}

	return previousKey.KeyId, out, nil
}
