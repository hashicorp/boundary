// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package alias

import (
	"context"
	"strings"
	"sync"

	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/sdk/pbs/controller/protooptions"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
)

func init() {
	// register all proto fields that are aliasable.
	protoregistry.GlobalTypes.RangeMessages(func(m protoreflect.MessageType) bool {
		registerAliasableFields(m.Descriptor())
		return true
	})
}

var globalAliasableRegistry sync.Map

func registerAliasableFields(d protoreflect.MessageDescriptor) {
	fields := d.Fields()
	for i := 0; i < fields.Len(); i++ {
		f := fields.Get(i)
		name := f.FullName()
		opts, ok := f.Options().(*descriptorpb.FieldOptions)
		if !ok {
			continue
		}
		isAliasable := proto.GetExtension(opts, protooptions.E_Aliasable).(bool)
		if isAliasable {
			globalAliasableRegistry.Store(name, struct{}{})
		}
	}
}

func ResolutionInterceptor(
	ctx context.Context,
	aliasRepoFn func() (*Repository, error),
) grpc.UnaryServerInterceptor {
	const op = "alias.ResolutionInterceptor"

	return func(interceptorCtx context.Context,
		req any,
		_ *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler) (any, error,
	) {
		reqMsg, ok := req.(proto.Message)
		if !ok {
			return nil, handlers.InvalidArgumentErrorf("The request was not a proto.Message.", nil)
		}

		r, err := aliasRepoFn()
		if err != nil {
			return nil, err
		}
		interceptorCtx, err = transformRequest(interceptorCtx, reqMsg, r)
		return handler(interceptorCtx, req)
	}
}

// aliasLookup is an interface for looking up an alias by its value.
type aliasLookup interface {
	lookupAliasByValue(ctx context.Context, value string) (*Alias, error)
}

// transformRequest transforms the request by replacing alias values with their
// corresponding destination ids. If no alias is found or the alias has no
// destination id, an error is returned.
func transformRequest(ctx context.Context, req proto.Message, lookup aliasLookup) (context.Context, error) {
	r := req.ProtoReflect()
	fields := r.Descriptor().Fields()
	for i := 0; i < fields.Len(); i++ {
		f := fields.Get(i)
		if f.Kind() != protoreflect.StringKind {
			continue
		}
		if _, ok := globalAliasableRegistry.Load(f.FullName()); !ok {
			continue
		}
		v := r.Get(f).String()
		if !maybeAlias(v) {
			continue
		}

		// Special case the authorize session request, as it can be ambiguous
		// if the value is an alias or a target name with a scope id/name
		if f.FullName() == (&pbs.AuthorizeSessionRequest{}).ProtoReflect().Descriptor().Fields().ByName("id").FullName() {
			// If the scope is also provided, then we know the value is a target name
			if r.Has(fields.ByName("scope_id")) || r.Has(fields.ByName("scope_name")) {
				continue
			}
		}

		a, err := lookup.lookupAliasByValue(ctx, v)
		if err != nil {
			return ctx, err
		}
		if a == nil {
			return ctx, handlers.ApiErrorWithCodeAndMessage(codes.NotFound, "resource alias not found with value %q", v)
		}
		if a.DestinationId == "" {
			return ctx, handlers.ApiErrorWithCodeAndMessage(codes.NotFound, "resource not found for alias value %q", v)
		}
		r.Set(f, protoreflect.ValueOfString(a.DestinationId))
		ctx = setCtxAliasInfo(ctx, a)
	}

	return ctx, nil
}

// maybeAlias returns true if the input string is a candidate for being an alias.
func maybeAlias(s string) bool {
	return !strings.Contains(s, "_") &&
		len(s) > 0
}

type key int

var aliasCtxKey key

func setCtxAliasInfo(ctx context.Context, a *Alias) context.Context {
	return context.WithValue(ctx, aliasCtxKey, a)
}

func GetInfoFromContext(ctx context.Context) *Alias {
	v, ok := ctx.Value(aliasCtxKey).(*Alias)
	if !ok {
		return nil
	}
	return v
}
