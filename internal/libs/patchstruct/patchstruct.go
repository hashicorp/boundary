package patchstruct

import "google.golang.org/protobuf/types/known/structpb"

// Patch updates the struct found in dst with the values found in src. The
// intent of this helper is to provide a fallback mechanism for subtype
// attributes when the actual schema of the subtype attributes are unknown. As
// such, it's preferred to use other methods (such as mask mapping) when an
// actual message for the subtype is known.
//
// The following rules apply:
//
// * The source (src) map is merged into the destination map (dst).
//
// * Values are overwritten by the source map if they exist in both.a
//
// * Values are deleted from the destination if they are set to null in the
//   source.
//
// * Maps are recursively applied, meaning that a nested map at key "foo" in
//   the destination would be patched with a map at key "foo" in the
//   source.
//
// * A map in the destination is overwritten by a non-map in the source,
//   and a non-map in the destination is overwritten by a map in the
//   source.
//
// Patch returns the updated map as a copy, dst and src are not altered.
func Patch(dst, src *structpb.Struct) *structpb.Struct {
	result, err := structpb.NewStruct(patchM(dst.AsMap(), src.AsMap()))
	if err != nil {
		// Should never error as values are source from structpb values
		panic(err)
	}

	return result
}

func patchM(dst, src map[string]interface{}) map[string]interface{} {
	for k, v := range src {
		switch x := v.(type) {
		case map[string]interface{}:
			if y, ok := dst[k].(map[string]interface{}); ok {
				// If the value in dst a map, continue to patch
				dst[k] = patchM(y, x)
			} else {
				// Overwrite
				dst[k] = x
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
