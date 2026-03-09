// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package subtypes

import (
	"context"
	"fmt"
	"sync"

	"github.com/hashicorp/boundary/internal/errors"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

var globalTransformationRegistry = &transformationRegistry{
	requestTransformationFuncs:  make(map[protoreflect.FullName]TransformationFunc),
	responseTransformationFuncs: make(map[protoreflect.FullName]TransformationFunc),
}

// transformationRegistry stores registered request and response
// transformation functions.
type transformationRegistry struct {
	requestTransformationFuncs  map[protoreflect.FullName]TransformationFunc
	responseTransformationFuncs map[protoreflect.FullName]TransformationFunc

	sync.RWMutex
}

func (r *transformationRegistry) registerRequestTransformationFunc(ctx context.Context, msg proto.Message, transformFn TransformationFunc) error {
	r.Lock()
	defer r.Unlock()

	fqn := msg.ProtoReflect().Descriptor().FullName()
	const op = "subtypes.(transformationRegistry).RegisterRequestTransformationFunc"
	if _, present := r.requestTransformationFuncs[fqn]; present {
		return errors.New(
			ctx,
			errors.SubtypeAlreadyRegistered,
			op,
			fmt.Sprintf("proto type %q already has a request transformation function registered", fqn),
		)
	}
	r.requestTransformationFuncs[fqn] = transformFn
	return nil
}

func (r *transformationRegistry) registerResponseTransformationFunc(ctx context.Context, msg proto.Message, transformFn TransformationFunc) error {
	r.Lock()
	defer r.Unlock()

	fqn := msg.ProtoReflect().Descriptor().FullName()
	const op = "subtypes.(transformationRegistry).RegisterResponseTransformationFunc"
	if _, present := r.responseTransformationFuncs[fqn]; present {
		return errors.New(
			ctx,
			errors.SubtypeAlreadyRegistered,
			op,
			fmt.Sprintf("proto type %q already has a response transformation function registered", fqn),
		)
	}
	r.responseTransformationFuncs[fqn] = transformFn
	return nil
}

// TransformationFunc defines the signature used to transform
// protobuf message attributes. The proto.Message is mutated in place.
type TransformationFunc func(context.Context, proto.Message) error

// RegisterRequestTransformationFunc registers a transformation function for
// the provided message. The message should be used as a request parameter to
// a service method. The provided callback is guaranteed to only be called with messages
// of the same type as the provided message.
func RegisterRequestTransformationFunc(msg proto.Message, transformFn TransformationFunc) error {
	ctx := context.TODO()
	return globalTransformationRegistry.registerRequestTransformationFunc(ctx, msg, transformFn)
}

// RegisterResponseTransformationFunc registers a transformation function for
// the provided message. The message should be used as a response parameter to
// a service method. The provided callback is guaranteed to only be called with messages
// of the same type as the provided message.
func RegisterResponseTransformationFunc(msg proto.Message, transformFn TransformationFunc) error {
	ctx := context.TODO()
	return globalTransformationRegistry.registerResponseTransformationFunc(ctx, msg, transformFn)
}
