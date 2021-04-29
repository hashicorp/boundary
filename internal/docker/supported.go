// +build linux darwin windows

package docker

import (
	"database/sql"
	"fmt"
	"os"
	"strings"

	"github.com/ory/dockertest/v3"
)

func init() {
	StartDbInDocker = startDbInDockerSupported
}

func startDbInDockerSupported(dialect string, opt ...Option) (cleanup func() error, retURL, container string, err error) {
	// TODO: Debug what part of this method is actually causing race condition issues with our test and fix.
	mx.Lock()
	defer mx.Unlock()
	pool, err := dockertest.NewPool("")
	if err != nil {
		return func() error { return nil }, "", "", fmt.Errorf("could not connect to docker: %w", err)
	}

	var resource *dockertest.Resource
	var url, tag string

	opts := GetOpts(opt...)
	if opts.withContainerImage != "" {
		dialect, tag, err = splitImage(opt...)
		if err != nil {
			return func() error { return nil }, "", "", fmt.Errorf("error parsing reference: %w", err)
		}
	}

	switch dialect {
	case "postgres":
		switch {
		case os.Getenv("BOUNDARY_TESTING_PG_URL") != "":
			url = os.Getenv("BOUNDARY_TESTING_PG_URL")
			return func() error { return nil }, url, "", nil

		default:
			resource, err = pool.Run(dialect, tag, []string{"POSTGRES_PASSWORD=password", "POSTGRES_DB=boundary"})
			url = "postgres://postgres:password@localhost:%s?sslmode=disable"
			if err == nil {
				url = fmt.Sprintf("postgres://postgres:password@%s/boundary?sslmode=disable", resource.GetHostPort("5432/tcp"))
			}
		}

	default:
		panic(fmt.Sprintf("unknown dialect %q", dialect))
	}
	if err != nil {
		return func() error { return nil }, "", "", fmt.Errorf("could not start resource: %w", err)
	}

	cleanup = func() error {
		return cleanupDockerResource(pool, resource)
	}

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
		return cleanup, "", "", fmt.Errorf("could not ping postgres on startup: %w", err)
	}

	return cleanup, url, resource.Container.Name, nil
}

// cleanupDockerResource will clean up the dockertest resources (postgres)
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
	return fmt.Errorf("failed to cleanup local container: %s", err)
}

// splitImage takes the WithDatabaseImage option and separates
// it into repo + tag. If a tag is not found, it sets the tag to latest
func splitImage(opt ...Option) (string, string, error) {
	opts := GetOpts(opt...)

	separated := strings.Split(opts.withContainerImage, ":")
	separatedlen := len(separated)

	switch separatedlen {
	case 1:
		return separated[0], "11", nil
	case 2:
		return separated[0], separated[1], nil

	default:
		return "", "", fmt.Errorf("valid reference format is repo:tag, got: %s", opts.withContainerImage)

	}

}
