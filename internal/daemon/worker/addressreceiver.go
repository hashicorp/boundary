// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package worker

import (
	"google.golang.org/grpc/resolver"
	"google.golang.org/grpc/resolver/manual"
)

type receiverType uint

const (
	UnknownReceiverType receiverType = iota
	grpcResolverReceiverType
	secondaryConnectionReceiverType
)

// String returns a string representation of the receiverType
func (s receiverType) String() string {
	return [...]string{
		"unknown",
		"grpcResolver",
		"secondaryConnections",
	}[s]
}

// addressReceiver allows the initializing and setting of addresses. Since a
// main use case of this interface is to use it in grpc dialing it satisfies
// a grpc resolver.Builder interface as well.
type addressReceiver interface {
	InitialAddresses([]string)
	SetAddresses([]string)
	Type() receiverType
}

// grpcResolverReceiver is an addressReceiver which wraps a grpc manual.Resolver
// InitialAddresses is passed onto the Resolver's InitialState method and
// SetAddresses  is passed onto the Resolver's UpdateState call.
type grpcResolverReceiver struct {
	*manual.Resolver
}

// IsDialingListener always returns
func (*grpcResolverReceiver) Type() receiverType {
	return grpcResolverReceiverType
}

func (r grpcResolverReceiver) getState(addrs []string) resolver.State {
	var rAddrs []resolver.Address
	for _, a := range addrs {
		rAddrs = append(rAddrs, resolver.Address{Addr: a})
	}
	return resolver.State{Addresses: rAddrs}
}

func (r *grpcResolverReceiver) InitialAddresses(addrs []string) {
	r.Resolver.InitialState(r.getState(addrs))
}

func (r *grpcResolverReceiver) SetAddresses(addrs []string) {
	r.Resolver.UpdateState(r.getState(addrs))
}
