// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package patchstruct

import (
	"fmt"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
)

// PatchStruct updates the struct found in dst with the values found in src. The
// intent of this helper is to provide a fallback mechanism for subtype
// attributes when the actual schema of the subtype attributes are unknown. As
// such, it's preferred to use other methods (such as mask mapping) when an
// actual message for the subtype is known.
//
// The following rules apply:
//
//   - The source (src) map is merged into the destination map (dst). If the
//     source map is nil, the destination will be a valid, but empty, map.
//
//   - Values are overwritten by the source map if they exist in both.
//
//   - Values are deleted from the destination if they are set to null in the
//     source.
//
//   - Maps are recursively applied, meaning that a nested map at key "foo" in
//     the destination would be patched with a map at key "foo" in the
//     source.
//
//   - A map in the destination is overwritten by a non-map in the source,
//     and a non-map in the destination is overwritten by a map in the
//     source.
//
// PatchStruct returns the updated map as a copy, dst and src are not altered.
func PatchStruct(dst, src *structpb.Struct) *structpb.Struct {
	if src == nil {
		ret, _ := structpb.NewStruct(nil)
		return ret
	}
	result, err := structpb.NewStruct(patchM(dst.AsMap(), src.AsMap()))
	if err != nil {
		// Should never error as values are source from structpb values
		panic(err)
	}

	return result
}

// PatchBytes follows the same rules as above with PatchStruct, but instead of
// patching structpb.Structs, it patches the protobuf encoding. An error is
// returned if there are issues working with the data. If src is nil or empty,
// the result is a marshaled, empty struct.
func PatchBytes(dst, src []byte) ([]byte, error) {
	srcpb, dstpb := new(structpb.Struct), new(structpb.Struct)
	if len(src) != 0 {
		if err := proto.Unmarshal(dst, dstpb); err != nil {
			return nil, fmt.Errorf("error reading destination data: %w", err)
		}
		if err := proto.Unmarshal(src, srcpb); err != nil {
			return nil, fmt.Errorf("error reading source data: %w", err)
		}
		dstpb = PatchStruct(dstpb, srcpb)
	} else {
		dstpb, _ = structpb.NewStruct(nil)
	}

	result, err := proto.Marshal(dstpb)
	if err != nil {
		return nil, fmt.Errorf("error writing result data: %w", err)
	}

	return result, nil
}

func patchM(dst, src map[string]any) map[string]any {
	for k, v := range src {
		switch x := v.(type) {
		case map[string]any:
			if y, ok := dst[k].(map[string]any); ok {
				// If the value in dst a map, continue to patch
				dst[k] = patchM(y, x)
			} else {
				// Overwrite after stripping out keys to nil values
				newX := patchM(make(map[string]any), x)
				dst[k] = newX
			}

		default:
			if v == nil {
				// explicit null values delete values at that key in dst
				delete(dst, k)
			} else {
				// Anything else gets overwritten
				dst[k] = v
			}
		}
	}

	return dst
}
