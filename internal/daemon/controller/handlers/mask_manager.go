// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package handlers

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/internal/errors"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"

	pb "github.com/hashicorp/boundary/sdk/pbs/controller/protooptions"
)

type MaskManager map[string]string

type (
	MaskDestination []protoreflect.ProtoMessage
	MaskSource      []protoreflect.ProtoMessage
)

// NewMaskManager returns a mask manager that can translate field masks into
// the first proto from all subsequent protos assuming they are both using the
// mask_mapping custom option.  Error is returned if no mappings are
// found or if one of the passed protos has a mapping that doesn't reciprocate.
func NewMaskManager(ctx context.Context, dest MaskDestination, src MaskSource) (MaskManager, error) {
	const op = "handlers.NewMaskManager"
	srcToDest, err := mapFromProto(ctx, src)
	if err != nil {
		return nil, err
	}
	destToSrc, err := mapFromProto(ctx, dest)
	if err != nil {
		return nil, err
	}

	result := make(map[string]string)
	for k, v := range srcToDest {
		ov, ok := destToSrc[v]
		if !ok || ov != k {
			return nil, errors.New(ctx, errors.Encode, op, fmt.Sprintf("mapping src field %q maps to %q, dest %q maps to %q", k, v, v, ov))
		}
		result[k] = v
	}

	// Now check to make sure there aren't any dangling dest mappings.
	for k, v := range destToSrc {
		if ov, ok := srcToDest[v]; !ok || ov != k {
			return nil, errors.New(ctx, errors.Encode, op, fmt.Sprintf("mapping src field %q maps to %q, dest %q maps to %q", k, v, v, ov))
		}
	}

	if len(result) == 0 {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "mask mapping generated is zero")
	}

	return result, nil
}

func mapFromProto(ctx context.Context, ps []protoreflect.ProtoMessage) (map[string]string, error) {
	const op = "handlers.mapFromProto"
	mapping := make(map[string]string)
	for _, p := range ps {
		m := p.ProtoReflect()
		fields := m.Descriptor().Fields()
		for i := 0; i < fields.Len(); i++ {
			f := fields.Get(i)
			opts := f.Options().(*descriptorpb.FieldOptions)
			if nameMap := proto.GetExtension(opts, pb.E_MaskMapping).(*pb.MaskMapping); !proto.Equal(nameMap, &pb.MaskMapping{}) && nameMap != nil {
				if _, ok := mapping[nameMap.GetThis()]; ok {
					return nil, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("duplicate mapping from field %q with the mapping key %q", f.Name(), nameMap.GetThis()))
				}
				mapping[nameMap.GetThis()] = nameMap.GetThat()
			}
		}
	}
	return mapping, nil
}

// Translate takes a field mask's paths and returns paths translated for the
// destination's protobuf.  If a translation doesn't exist for a specific path
// entry then nothing is returned for that specific path entry unless
// passedThroughPrefix is used and applies to that entry.
//
// passedThroughPrefix is helpful when the field mask's paths cannot be mapped
// through the mask mapper for some reason (we don't know the mapping at compile
// time, for example) but we still want certain paths to be passed on.  If a
// path entry isn't mapped to anything by the MaskManager but does contain
// a prefix which matches a passedThroughPrefix it will be added unmodified
// to the returned value.
func (m MaskManager) Translate(paths []string, passedThroughPrefix ...string) []string {
	var result []string
	for _, v := range paths {
		vSplit := strings.Split(v, ",")
		for _, v := range vSplit {
			candidate := strings.TrimSpace(v)
			if ov, ok := m[candidate]; ok {
				result = append(result, ov)
			} else {
				for _, pre := range passedThroughPrefix {
					if strings.HasPrefix(candidate, pre) {
						result = append(result, candidate)
						break
					}
				}
			}
		}
	}
	return result
}

func MaskContains(paths []string, s string) bool {
	for _, p := range paths {
		if p == s {
			return true
		}
	}
	return false
}

func MaskContainsPrefix(paths []string, s string) bool {
	for _, p := range paths {
		if strings.Contains(p, s) {
			return true
		}
	}
	return false
}
