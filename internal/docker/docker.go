package docker

import (
	"errors"
	"sync"
)

var (
	StartDbInDocker func(opt ...Option) (func() error, string, string, error) = startDbInDockerUnsupported

	ErrDockerUnsupported = errors.New("docker is not currently supported on this platform")

	mx = sync.Mutex{}
)

func startDbInDockerUnsupported(opt ...Option) (cleanup func() error, retURL, container string, err error) {
	return nil, "", "", ErrDockerUnsupported
}
