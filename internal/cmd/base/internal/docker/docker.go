// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package docker

import (
	"errors"
	"sync"
)

var (
	StartDbInDocker func(dialect string, opt ...Option) (func() error, string, string, error) = startDbInDockerUnsupported

	ErrDockerUnsupported = errors.New("docker is not currently supported on this platform")

	mx = sync.Mutex{}
)

func startDbInDockerUnsupported(dialect string, opt ...Option) (cleanup func() error, retURL, container string, err error) {
	return nil, "", "", ErrDockerUnsupported
}
