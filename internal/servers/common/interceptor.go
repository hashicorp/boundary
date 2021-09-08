package common

import (
	"context"

	"github.com/hashicorp/boundary/internal/observability/event"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

// InboundAuditInterceptor is an unary interceptor that writes the inbound req
// proto message to the audit event.
//
// TODO jlambrt 9/2021: make changes required to use this interceptor.
func InboundAuditInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		if p, ok := req.(proto.Message); ok {
			event.WriteAudit(ctx, "OutgoingAuditInterceptor", event.WithRequest(&event.Request{Details: p}))
		}
		return handler(ctx, req)
	}
}
