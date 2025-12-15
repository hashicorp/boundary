// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

//go:build windows

package connect

import (
	"os"
)

// endProcess kills the provided os process
func endProcess(p *os.Process) error {
	if p == nil {
		return nil
	}
	return p.Kill()
}
