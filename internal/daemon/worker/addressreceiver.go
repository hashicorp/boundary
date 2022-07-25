package worker

import (
	"context"

	"google.golang.org/grpc/resolver"
	"google.golang.org/grpc/resolver/manual"
)

var extraAddressReceivers = noopAddressReceivers

func noopAddressReceivers(context.Context, *Worker) ([]addressReceiver, error) {
	return nil, nil
}

// addressReceiver allows the initializing and setting of addresses. Since a
// main use case of this interface is to use it in grpc dialing it satisfies
// a grpc resolver.Builder interface as well.
type addressReceiver interface {
	InitialAddresses([]string)
	SetAddresses([]string)
}

// grpcResolverReceiver is an addressReceiver which wraps a grpc manual.Resolver
// InitialAddresses is passed onto the Resolver's InitialState method and
// SetAddresses  is passed onto the Resolver's UpdateState call.
type grpcResolverReceiver struct {
	*manual.Resolver
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
