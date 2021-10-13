package patchstruct

import "google.golang.org/protobuf/types/known/structpb"

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
