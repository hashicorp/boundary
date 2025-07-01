// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package encrypt

import (
	"reflect"
	"strings"
)

type tagInfo struct {
	Classification DataClassification
	Operation      FilterOperation
}

func getClassificationFromTag(f reflect.StructTag, opt ...Option) *tagInfo {
	t, ok := f.Lookup(DataClassificationTagName)

	if !ok {
		return &tagInfo{
			Classification: UnknownClassification,
			Operation:      UnknownOperation,
		}
	}
	return getClassificationFromTagString(t, opt...)
}

// getClassificationFromTagString takes a tag (as a string) and supports the
// WithFilterOperations option. It will parse the tag string and determine its
// DataClassification and Operation which will be returned in a tagInfo pointer.
//
// The default classification == UnknownOperation and the default operation ==
// NoOperation. The classification and operation are delimited by a comma ","
func getClassificationFromTagString(tag string, opt ...Option) *tagInfo {
	const op = "node.getClassificationFromTagString"
	segs := strings.Split(tag, ",") // will always return at least 1 segment

	var operation FilterOperation
	switch len(segs) {
	case 0, 1:
		operation = NoOperation
	default:
		operation = convertToOperation(segs[1])
	}
	if operation == UnknownOperation {
		// setting a reasonable default is better than returning an ambiguous error
		operation = NoOperation
	}

	classification := DataClassification(segs[0])
	opts := getOpts(opt...)
	if operationOverride, ok := opts.withFilterOperations[classification]; ok {
		return &tagInfo{
			Classification: classification,
			Operation:      operationOverride,
		}
	}

	defaultOps := DefaultFilterOperations()
	switch classification {
	case PublicClassification:
		return &tagInfo{
			Classification: PublicClassification,
			Operation:      defaultOps[PublicClassification],
		}
	case SensitiveClassification:
		if operation == NoOperation {
			// set a default
			operation = defaultOps[SensitiveClassification]
		}
		return &tagInfo{
			Classification: SensitiveClassification,
			Operation:      operation,
		}
	case SecretClassification:
		if operation == NoOperation {
			// set a default
			operation = defaultOps[SecretClassification]
		}
		return &tagInfo{
			Classification: SecretClassification,
			Operation:      operation,
		}
	default:
		// returning a reasonable default is better than returning an ambiguous error
		return &tagInfo{
			Classification: UnknownClassification,
			Operation:      UnknownOperation,
		}
	}
}

// DefaultFilterOperations returns a map of DataClassification to its default
// FilterOperation (when no overrides are configured for the filter node).
func DefaultFilterOperations() map[DataClassification]FilterOperation {
	return map[DataClassification]FilterOperation{
		PublicClassification:    NoOperation,
		SensitiveClassification: EncryptOperation,
		SecretClassification:    RedactOperation,
	}
}
