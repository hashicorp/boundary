// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package alias

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/sdk/pbs/controller/protooptions"
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

type registrationInfo struct {
	unaliasableWithFields []string
}

// globalAliasableRegistry is a map of proto field's FullName to registrationInfo.
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
		aliasableInfo := proto.GetExtension(opts, protooptions.E_Aliasable).(*protooptions.AliasInfo)
		if aliasableInfo != nil {
			ri := &registrationInfo{unaliasableWithFields: aliasableInfo.GetUnlessSet().GetFields()}
			globalAliasableRegistry.Store(name, ri)
		}
	}
}

// aliasLookup is an interface for looking up an alias by its value.
type aliasLookup interface {
	lookupAliasByValue(ctx context.Context, value string) (*Alias, error)
}

// ResolveRequestIds transforms the request by replacing aliasable field values
// with their corresponding destination ids. A field is aliasable depending on
// if and how the custom proto option "custom_options.v1.aliasable" is set on
// it. When the option is set on a field, it can be marked as always aliasable,
// in which case the field will always be checked for an alias value on the field
// or it can be marked as aliasable unless other specified fields on the same
// message is set.
// If no alias is found or the alias has no destination id, an error is returned.
func ResolveRequestIds(ctx context.Context, req proto.Message, lookup aliasLookup) (context.Context, error) {
	const op = "alias.ResolveRequestIds"
	r := req.ProtoReflect()
	fields := r.Descriptor().Fields()

nextField:
	for i := 0; i < fields.Len(); i++ {
		f := fields.Get(i)
		if f.Kind() != protoreflect.StringKind {
			continue
		}
		aiVal, ok := globalAliasableRegistry.Load(f.FullName())
		if !ok {
			continue
		}
		ai, ok := aiVal.(*registrationInfo)
		if !ok {
			return ctx, errors.New(ctx, errors.Internal, op, fmt.Sprintf("unable to cast aliasable info for field %q", f.FullName()))
		}

		v := r.Get(f).String()
		if !maybeAlias(v) {
			continue
		}

		for _, fieldName := range ai.unaliasableWithFields {
			if r.Has(fields.ByName(protoreflect.Name(fieldName))) {
				continue nextField
			}
		}

		a, err := lookup.lookupAliasByValue(ctx, v)
		if err != nil {
			return ctx, err
		}
		if a == nil {
			return ctx, errors.New(ctx, errors.NotFound, op, fmt.Sprintf("resource alias not found with value %q", v), errors.WithoutEvent())
		}
		if a.DestinationId == "" {
			return ctx, errors.New(ctx, errors.NotFound, op, fmt.Sprintf("resource not found for alias value %q", v), errors.WithoutEvent())
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

// FromContext returns the Alias from the context, if it exists. It will only
// exist if the original request contained an alias in a field marked as
// aliasable in the proto definition, and the alias was successfully resolved.
func FromContext(ctx context.Context) *Alias {
	v, ok := ctx.Value(aliasCtxKey).(*Alias)
	if !ok {
		return nil
	}
	return v
}
