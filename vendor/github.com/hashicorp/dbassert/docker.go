// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

// +build linux darwin windows

package dbassert

import (
	"database/sql"
	"fmt"
	"strings"

	"github.com/ory/dockertest/v3"
)

func init() {
	StartDbInDocker = startDbInDockerSupported
}

// StartDbInDocker starts up the dialect db in the local docker.
func startDbInDockerSupported(dialect string) (cleanup func() error, retURL, container string, err error) {
	pool, err := dockertest.NewPool("")
	if err != nil {
		return func() error { return nil }, "", "", fmt.Errorf("could not connect to docker: %w", err)
	}

	var resource *dockertest.Resource
	var url string
	switch dialect {
	case "postgres":
		resource, err = pool.Run("postgres", "latest", []string{"POSTGRES_PASSWORD=secret"})
		url = "postgres://postgres:secret@localhost:%s?sslmode=disable"
	default:
		panic(fmt.Sprintf("unknown dialect %q", dialect))
	}
	if err != nil {
		return func() error { return nil }, "", "", fmt.Errorf("could not start resource: %w", err)
	}

	cleanup = func() error {
		return cleanupDockerResource(pool, resource)
	}

	url = fmt.Sprintf(url, resource.GetPort("5432/tcp"))

	if err := pool.Retry(func() error {
		db, err := sql.Open(dialect, url)
		if err != nil {
			return fmt.Errorf("error opening %s dev container: %w", dialect, err)
		}

		if err := db.Ping(); err != nil {
			return err
		}
		defer db.Close()
		return nil
	}); err != nil {
		return func() error { return nil }, "", "", fmt.Errorf("could not connect to docker: %w", err)
	}

	return cleanup, url, resource.Container.Name, nil
}

// cleanupDockerResource will clean up the dockertest resources
func cleanupDockerResource(pool *dockertest.Pool, resource *dockertest.Resource) error {
	var err error
	for i := 0; i < 10; i++ {
		err = pool.Purge(resource)
		if err == nil {
			return nil
		}
	}
	if strings.Contains(err.Error(), "No such container") {
		return nil
	}
	return fmt.Errorf("Failed to cleanup local container: %s", err)
}
