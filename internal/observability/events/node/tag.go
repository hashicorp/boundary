package node

import (
	"reflect"
	"strings"
)

type tagInfo struct {
	Classification DataClassification
	Operation      FilterOperation
}

func getClassificationFromTag(f reflect.StructTag) *tagInfo {
	t, ok := f.Lookup(DataClassificationTagName)

	if !ok {
		return &tagInfo{
			Classification: UnknownClassification,
			Operation:      UnknownOperation,
		}
	}
	return getClassificationFromTagString(t)
}

func getClassificationFromTagString(tag string) *tagInfo {
	const op = "node.getClassificationFromTagString"
	segs := strings.Split(tag, ",")

	if len(segs) == 0 {
		return &tagInfo{
			Classification: UnknownClassification,
			Operation:      UnknownOperation,
		}
	}

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

	switch DataClassification(segs[0]) {
	case PublicClassification:
		return &tagInfo{
			Classification: PublicClassification,
			Operation:      NoOperation,
		}
	case SensitiveClassification:
		if operation == NoOperation {
			// set a default
			operation = EncryptOperation
		}
		return &tagInfo{
			Classification: SensitiveClassification,
			Operation:      operation,
		}
	case SecretClassification:
		if operation == NoOperation {
			// set a default
			operation = RedactOperation
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
