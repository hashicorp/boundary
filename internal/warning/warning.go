// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package warning

import (
	"context"
	"sync"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/event"
	pbwarnings "github.com/hashicorp/boundary/internal/gen/controller/api"
)

type warningKey int

var (
	warnerContextKey warningKey
	warningHeader    = "x-boundary-warnings"
)

// warner holds all the warnings generated for a given user facing API request.
// It is thread safe.
type warner struct {
	warnings []*pbwarnings.Warning

	// l protects each of the slices in this struct.
	l sync.Mutex
}

func Warn(ctx context.Context, d apiWarning) error {
	const op = "apiWarning.ForField"
	w, ok := ctx.Value(warnerContextKey).(*warner)
	if !ok {
		return errors.New(ctx, errors.InvalidParameter, op, "context doesn't contain apiWarning functionality")
	}
	w.l.Lock()
	defer w.l.Unlock()
	if wp := d.toProto(); wp != nil {
		w.warnings = append(w.warnings, wp)
	}
	return nil
}

func newContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, warnerContextKey, &warner{})
}

func convertToGrpcHeaders(ctx context.Context) error {
	const op = "apiWarning.convertToGrpcHeaders"
	w, ok := ctx.Value(warnerContextKey).(*warner)
	if !ok {
		return errors.New(ctx, errors.InvalidParameter, op, "context doesn't have warner")
	}
	w.l.Lock()
	defer w.l.Unlock()

	if len(w.warnings) == 0 {
		return nil
	}
	pbWar := &pbwarnings.WarningResponse{
		Warnings: w.warnings,
	}
	var buf []byte
	var err error
	if buf, err = protojson.Marshal(pbWar); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("unable to marshal warnings"))
	}
	if err := grpc.SetHeader(ctx, metadata.Pairs(warningHeader, string(buf))); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("unable to set apiWarning grpc header"))
	}
	return nil
}

// OutgoingHeaderMatcher provides a runtime.HeaderMatcherFunc that can be used
// as an option when creating a new grpc gateway server muxer, and specifies
// the boundary apiWarning headers which can be forwarded on to the requesting client.
func OutgoingHeaderMatcher() runtime.HeaderMatcherFunc {
	return func(s string) (string, bool) {
		if s == warningHeader {
			return warningHeader, true
		}
		return "", false
	}
}

// GrpcInterceptor intercepts warnings as reported by the handlers and populates
// them in a specific header.
func GrpcInterceptor(outerCtx context.Context) grpc.UnaryServerInterceptor {
	const op = "controller.warningInterceptor"
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		ctx = newContext(ctx)
		h, handlerErr := handler(ctx, req)
		if err := convertToGrpcHeaders(ctx); err != nil {
			event.WriteError(outerCtx, op, err)
		}
		return h, handlerErr
	}
}
