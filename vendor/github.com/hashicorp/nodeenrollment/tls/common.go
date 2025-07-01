// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package tls

import (
	"fmt"
	"strings"
)

// We can't go above 255 characters per chunk; capping here just leaves some
// room for the internal bits like the chunk number and hyphen formatting
const maxNextProtoSizeWithBuffer = 240

// BreakIntoNextProtos takes in a prefix and a value and breaks it into a
// chunks
func BreakIntoNextProtos(prefix, value string) ([]string, error) {
	const op = "nodeenrollment.tls.BreakIntoNextProtos"
	switch {
	case len(prefix) == 0:
		return nil, fmt.Errorf("(%s) empty prefix provided", op)
	case len(value) == 0:
		return nil, fmt.Errorf("(%s) empty value provided", op)
	}
	var count int
	maxSize := maxNextProtoSizeWithBuffer - len(prefix)
	ret := make([]string, 0, len(value)/maxSize+1)
	for i := 0; i < len(value); i += maxSize {
		end := i + maxSize
		if end > len(value) {
			end = len(value)
		}
		ret = append(ret, fmt.Sprintf("%s%02d-%s", prefix, count, value[i:end]))
		count++
	}
	return ret, nil
}

// CombineFromNextProtos takes in a prefix and chunks and combines it from
// chunks
func CombineFromNextProtos(prefix string, chunks []string) (string, error) {
	const op = "nodeenrollment.tls.CombineFromNextProtos"
	switch {
	case len(prefix) == 0:
		return "", fmt.Errorf("(%s) empty prefix provided", op)
	case len(chunks) == 0:
		return "", fmt.Errorf("(%s) empty chunks provided", op)
	}
	var ret string
	for _, chunk := range chunks {
		// Strip that and the number
		if strings.HasPrefix(chunk, prefix) {
			ret += strings.TrimPrefix(chunk, prefix)[3:]
		}
	}
	return ret, nil
}
