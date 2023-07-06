// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package bsr

import (
	"context"
	"fmt"
)

// SummaryAllocFunc is a function that returns a summary type
type SummaryAllocFunc func(ctx context.Context) Summary

type SummaryAllocFuncRegistry map[Protocol]map[ContainerType]SummaryAllocFunc

func (r SummaryAllocFuncRegistry) Get(p Protocol, c ContainerType) (SummaryAllocFunc, bool) {
	protocol, ok := r[p]
	if !ok {
		return nil, false
	}
	af, ok := protocol[c]
	return af, ok
}

var SummaryAllocFuncs SummaryAllocFuncRegistry

// RegisterSummaryAllocFunc registers a SummaryAllocFunc for the given Protocol.
// A given Protocol and Container can only have one SummaryAllocFunc function
// registered.
func RegisterSummaryAllocFunc(p Protocol, c ContainerType, af SummaryAllocFunc) error {
	const op = "bsr.RegisterSummaryAllocFunc"

	if SummaryAllocFuncs == nil {
		SummaryAllocFuncs = make(map[Protocol]map[ContainerType]SummaryAllocFunc)
	}

	protocol, ok := SummaryAllocFuncs[p]
	if !ok {
		protocol = make(map[ContainerType]SummaryAllocFunc)
	}

	_, ok = protocol[c]
	if ok {
		return fmt.Errorf("%s: %s %s: %w", op, p, c, ErrAlreadyRegistered)
	}
	protocol[c] = af
	SummaryAllocFuncs[p] = protocol
	return nil
}
