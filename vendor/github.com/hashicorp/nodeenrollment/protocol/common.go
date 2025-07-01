// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package protocol

import (
	"context"

	"github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/types"
)

// FetchCredsFn is a function that is used when a node requests fetching its
// initial credentials. It returns a response or an error. This is called during
// TLS negotiation for the given ALPN proto.
//
// Note that options do not carry across gRPC; in practice this means they do
// not carry across multiple nodes. Only options meant for local use
// (WithRandomReader, WithStorageWrapper, WithLogger) etc. should be used, via
// the direct functions.
type FetchCredsFn = func(
	context.Context,
	nodeenrollment.Storage,
	*types.FetchNodeCredentialsRequest,
	...nodeenrollment.Option,
) (*types.FetchNodeCredentialsResponse, error)

// GenerateServerCertificatesFn is a function that is used when a node is
// connecting by the upstream node to fetch a certificate to present to the
// node. It returns a response or an error. This is called during TLS
// negotiation for the given ALPN proto.
//
// Note that options do not carry across gRPC; in practice this means they do
// not carry across multiple nodes. Only options meant for local use
// (WithRandomReader, WithStorageWrapper, WithLogger) etc. should be used, via
// the direct functions.
type GenerateServerCertificatesFn = func(
	context.Context,
	nodeenrollment.Storage,
	*types.GenerateServerCertificatesRequest,
	...nodeenrollment.Option,
) (*types.GenerateServerCertificatesResponse, error)
