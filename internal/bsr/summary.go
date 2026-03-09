// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package bsr

import (
	"context"
	"fmt"
)

// SummaryAllocFunc is a function that returns a summary type
type SummaryAllocFunc func(ctx context.Context) Summary

// summaryAllocFuncRegistry mappings of protocols and container type
// for each SummaryAllocFunc
type summaryAllocFuncRegistry map[Protocol]map[ContainerType]SummaryAllocFunc

func (r summaryAllocFuncRegistry) get(p Protocol, c ContainerType) (SummaryAllocFunc, bool) {
	protocol, ok := r[p]
	if !ok {
		return nil, false
	}
	af, ok := protocol[c]
	return af, ok
}

var summaryAllocFuncs summaryAllocFuncRegistry

// RegisterSummaryAllocFunc registers a SummaryAllocFunc for the given Protocol.
// A given Protocol and Container can only have one SummaryAllocFunc function
// registered.
func RegisterSummaryAllocFunc(p Protocol, c ContainerType, af SummaryAllocFunc) error {
	const op = "bsr.RegisterSummaryAllocFunc"

	if summaryAllocFuncs == nil {
		summaryAllocFuncs = make(map[Protocol]map[ContainerType]SummaryAllocFunc)
	}

	protocol, ok := summaryAllocFuncs[p]
	if !ok {
		protocol = make(map[ContainerType]SummaryAllocFunc)
	}

	_, ok = protocol[c]
	if ok {
		return fmt.Errorf("%s: %s protocol with %s container: %w", op, p, c, ErrAlreadyRegistered)
	}
	protocol[c] = af
	summaryAllocFuncs[p] = protocol
	return nil
}
