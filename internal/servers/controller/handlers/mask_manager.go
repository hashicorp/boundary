package handlers

import (
	"fmt"
	"strings"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"

	pb "github.com/hashicorp/boundary/internal/gen/controller/protooptions"
)

type MaskManager map[string]string

// NewMaskManager returns a mask manager that can translate field masks from the first proto to the second assuming
// they are both using the mask_mapping custom option.  Error is returned if no mappings are found or if one of the
// passed protos has a mapping that doesn't reciprocate.
// TODO: Handle masks for nested messages.
func NewMaskManager(src, dest protoreflect.ProtoMessage) (MaskManager, error) {
	srcToDest := mapFromProto(src)
	destToSrc := mapFromProto(dest)

	result := make(map[string]string)
	for k, v := range srcToDest {
		ov, ok := destToSrc[v]
		if !ok || ov != k {
			return nil, fmt.Errorf("mapping src field %q maps to %q, dest %q maps to %q", k, v, v, ov)
		}
		result[k] = v
	}

	// Now check to make sure there aren't any dangling dest mappings.
	for k, v := range destToSrc {
		if ov, ok := srcToDest[v]; !ok || ov != k {
			return nil, fmt.Errorf("mapping dest field %q maps to %q, src %q maps to %q", k, v, v, ov)
		}
	}

	if len(result) == 0 {
		return nil, fmt.Errorf("size of mask mapping is 0")
	}

	return result, nil
}

func mapFromProto(p protoreflect.ProtoMessage) map[string]string {
	mapping := make(map[string]string)
	m := p.ProtoReflect()
	fields := m.Descriptor().Fields()
	for i := 0; i < fields.Len(); i++ {
		f := fields.Get(i)
		opts := f.Options().(*descriptorpb.FieldOptions)
		if nameMap := proto.GetExtension(opts, pb.E_MaskMapping).(*pb.MaskMapping); !proto.Equal(nameMap, &pb.MaskMapping{}) {
			mapping[nameMap.GetThis()] = nameMap.GetThat()
		}
	}
	return mapping
}

// Translate takes a field mask's paths and returns paths translated for the destination's protobuf.
func (m MaskManager) Translate(paths []string) []string {
	var result []string
	for _, v := range paths {
		vSplit := strings.Split(v, ",")
		for _, v := range vSplit {
			if ov, ok := m[strings.TrimSpace(v)]; ok {
				result = append(result, ov)
			}
		}
	}
	return result
}
