// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package rotation

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/registration"
	"github.com/hashicorp/nodeenrollment/types"
	"google.golang.org/protobuf/proto"
)

// RotateNodeCredentials accepts a request containing an encrypted fetch node
// credentials request and expects to be able to decrypt it via the key ID from
// the contained value. If valid, the credentials contained in the request will
// be registered to the system as valid credentials.
//
// Note that unlike RotateRootCertificates, where ownership of the roots belongs
// to this library, this is not a method that does nothing if it is not time to
// rotate. The node owns its credentials and should track when it's time to
// rotate and initiate rotation at that time.
//
// Although WithState is not explicitly supported, keep in mind that State will
// be transferred to the new NodeInformation. This fact can be used to match the
// new credentials to an external ID corresponding to the current credentials.
//
// Supported options:
// WithStorageWrapper/WithRandomReader/WithNotBeforeClockSkew/WithNotAfterClockSkew
// (passed through to AuthorizeNode and others), WithLogger
func RotateNodeCredentials(
	ctx context.Context,
	storage nodeenrollment.Storage,
	req *types.RotateNodeCredentialsRequest,
	opt ...nodeenrollment.Option,
) (*types.RotateNodeCredentialsResponse, error) {
	const op = "nodeenrollment.rotation.RotateNodeCredentials"

	switch {
	case nodeenrollment.IsNil(storage):
		return nil, fmt.Errorf("(%s) nil storage", op)
	case req == nil:
		return nil, fmt.Errorf("(%s) nil request", op)
	case len(req.CertificatePublicKeyPkix) == 0:
		return nil, fmt.Errorf("(%s) nil certificate public key", op)
	case len(req.EncryptedFetchNodeCredentialsRequest) == 0:
		return nil, fmt.Errorf("(%s) nil encrypted fetch node credentials request", op)
	}

	opts, err := nodeenrollment.GetOpts(opt...)
	if err != nil {
		return nil, fmt.Errorf("(%s) error parsing options: %w", op, err)
	}

	currentKeyId, err := nodeenrollment.KeyIdFromPkix(req.CertificatePublicKeyPkix)
	if err != nil {
		err := fmt.Errorf("error deriving current key id: %w", err)
		opts.WithLogger.Error(err.Error(), "op", op)
		return nil, fmt.Errorf("(%s) %s", op, err.Error())
	}

	// First we get our current node information and decrypt the fetch request
	nodeIdStorage, ok := storage.(nodeenrollment.NodeIdLoader)
	var nodeInfos *types.NodeInformationSet
	switch {
	// If we have a NodeId & storage supports NodeIdLoader, use it
	case req.NodeId != "" && ok:
		nodeInfos, err = types.LoadNodeInformationSetByNodeId(ctx, nodeIdStorage, req.NodeId, opt...)
		if err != nil {
			err := fmt.Errorf("error loading node informations for nodeId %s: %w", req.NodeId, err)
			opts.WithLogger.Error(err.Error(), "op", op)
			return nil, fmt.Errorf("(%s) %s", op, err.Error())
		}
	// Otherwise use the key id passed in
	default:
		currentNodeInfo, err := types.LoadNodeInformation(ctx, storage, currentKeyId, opt...)
		if err != nil {
			err := fmt.Errorf("error loading current node information: %w", err)
			opts.WithLogger.Error(err.Error(), "op", op)
			return nil, fmt.Errorf("(%s) %s", op, err.Error())
		}
		nodeInfos = &types.NodeInformationSet{
			Nodes: []*types.NodeInformation{currentNodeInfo},
		}
	}

	var currentNodeInfo *types.NodeInformation
	fetchRequest := new(types.FetchNodeCredentialsRequest)
	// Find the most current nodeInfo that can decrypt the request
	var fetchErrors []error
	for _, n := range nodeInfos.Nodes {
		err := nodeenrollment.DecryptMessage(
			ctx,
			req.EncryptedFetchNodeCredentialsRequest,
			n,
			fetchRequest,
			opt...,
		)
		if err == nil {
			currentNodeInfo = proto.Clone(n).(*types.NodeInformation)
			break
		}
		fetchErrors = append(fetchErrors, err)
	}
	if currentNodeInfo == nil {
		err := fmt.Errorf("no node information could decrypt the request: %w", errors.Join(fetchErrors...))
		opts.WithLogger.Error(err.Error(), "op", op)
		return nil, fmt.Errorf("(%s) %s", op, err.Error())
	}

	// At this point we've validated via the shared encryption key that it came
	// from that node so we trust the request. First we send it through
	// AuthorizeNode to register it and derive new keys; then, we call a fetch
	// on it and return the result, encrypted with the new keys.
	_, err = registration.AuthorizeNode(ctx, storage, fetchRequest, append(opt, nodeenrollment.WithState(currentNodeInfo.State))...)
	if err != nil {
		err := fmt.Errorf("error authorizing node with request: %w", err)
		opts.WithLogger.Error(err.Error(), "op", op)
		return nil, fmt.Errorf("(%s) %s", op, err.Error())
	}

	// We can use the same request as it is signed/valid. This will be encrypted
	// against the _new_ keys.
	fetchResp, err := registration.FetchNodeCredentials(ctx, storage, fetchRequest, opt...)
	if err != nil {
		err := fmt.Errorf("error getting new fetch credentials response: %w", err)
		opts.WithLogger.Error(err.Error(), "op", op)
		return nil, fmt.Errorf("(%s) %s", op, err.Error())
	}

	// Wrap that new message in one encrypted with the current keys
	encryptedResp, err := nodeenrollment.EncryptMessage(ctx, fetchResp, currentNodeInfo, opt...)
	if err != nil {
		err := fmt.Errorf("error encrypting fetch credentials response: %w", err)
		opts.WithLogger.Error(err.Error(), "op", op)
		return nil, fmt.Errorf("(%s) %s", op, err.Error())
	}

	return &types.RotateNodeCredentialsResponse{
		EncryptedFetchNodeCredentialsResponse: encryptedResp,
	}, nil
}
