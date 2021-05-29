package node

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/hashicorp/boundary/internal/errors"
)

type tagInfo struct {
	Classification DataClassification
	Operation      FilterOperation
}

func getClassificationFromTag(f reflect.StructTag) (*tagInfo, error) {
	t, ok := f.Lookup(DataClassificationTagName)

	if !ok {
		return &tagInfo{
			Classification: UnknownClassification,
			Operation:      UnknownOperation,
		}, nil
	}
	return getClassificationFromTagString(t)
}

func getClassificationFromTagString(tag string) (*tagInfo, error) {
	const op = "node.getClassificationFromTagString"
	segs := strings.Split(tag, ",")

	if len(segs) == 0 {
		return &tagInfo{
			Classification: UnknownClassification,
			Operation:      UnknownOperation,
		}, nil
	}
	classification := DataClassification(segs[0])
	if classification == UnknownClassification {
		return nil, errors.New(errors.InvalidParameter, op, fmt.Sprintf("invalid tag: classification of %s is unknown", classification))
	}

	var operation FilterOperation
	switch len(segs) {
	case 0, 1:
		operation = NoOperation
	default:
		operation = convertToOperation(segs[1])
	}
	if operation == UnknownOperation {
		return nil, errors.New(errors.InvalidParameter, op, fmt.Sprintf("invalid tag: filter operation of %s is unknown", operation))
	}

	switch classification {
	case PublicClassification:
		return &tagInfo{
			Classification: PublicClassification,
			Operation:      NoOperation,
		}, nil
	case SensitiveClassification:
		if operation == NoOperation {
			// set a default
			operation = EncryptOperation
		}
		return &tagInfo{
			Classification: SensitiveClassification,
			Operation:      operation,
		}, nil
	case SecretClassification:
		if operation == NoOperation {
			// set a default
			operation = RedactOperation
		}
		return &tagInfo{
			Classification: SecretClassification,
			Operation:      operation,
		}, nil
	default:
		return nil, errors.New(errors.InvalidParameter, op, fmt.Sprintf("invalid tag: classification of %s is unknown", classification))
	}
}
