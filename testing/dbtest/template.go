// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package dbtest

import (
	"context"
	"encoding/base64"
	"fmt"
	"math/rand"
	"os"

	// postgres dialect

	"github.com/hashicorp/boundary/internal/db/common"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-kms-wrapping/v2/aead"
	_ "github.com/jackc/pgx/v5/stdlib"
)

var (
	testDBPort = "5432"
	testDBHost = "127.0.0.1"
)

func init() {
	p := os.Getenv("TEST_DB_PORT")
	if p != "" {
		testDBPort = p
	}
	h := os.Getenv("TEST_DB_HOST")
	if h != "" {
		testDBHost = h
	}
}

// Dialects
const (
	Postgres = "postgres"
)

// BoundaryBenchmarksUserPassword is the password used for all users
// created by the boundary benchmarks dump generator.
const BoundaryBenchmarksUserPassword = "testpassword"

// Template Database Names
const (
	BoundaryTemplate                                 = "boundary_template"
	Template1                                        = "template1"
	Boundary1000Sessions10ConnsPerSession10Template  = "boundary_session_1000_10_10_template"
	Boundary1000Sessions10ConnsPerSession25Template  = "boundary_session_1000_10_25_template"
	Boundary1000Sessions10ConnsPerSession50Template  = "boundary_session_1000_10_50_template"
	Boundary1000Sessions10ConnsPerSession75Template  = "boundary_session_1000_10_75_template"
	Boundary1000Sessions10ConnsPerSession100Template = "boundary_session_1000_10_100_template"
	Boundary1000Sessions10ConnsPerSession500Template = "boundary_session_1000_10_500_template"
)

var supportedDialects = map[string]struct{}{
	Postgres: {},
}

var supportedTemplates = map[string]struct{}{
	BoundaryTemplate: {},
	Template1:        {},
	Boundary1000Sessions10ConnsPerSession10Template:  {},
	Boundary1000Sessions10ConnsPerSession25Template:  {},
	Boundary1000Sessions10ConnsPerSession50Template:  {},
	Boundary1000Sessions10ConnsPerSession75Template:  {},
	Boundary1000Sessions10ConnsPerSession100Template: {},
	Boundary1000Sessions10ConnsPerSession500Template: {},
}

const letterBytes = "abcdefghijklmnopqrstuvwxyz"
const (
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
)

const boundaryBenchmarksRootKey = "rootkey1rootkey1rootkey1rootkey1" // 32 bytes for AES-256

// GetBoundaryBenchmarksRootKeyWrapper returns the root key wrapper used for the benchmark dumps.
func GetBoundaryBenchmarksRootKeyWrapper(ctx context.Context) (wrapping.Wrapper, error) {
	wrap := aead.NewWrapper()
	_, err := wrap.SetConfig(ctx, wrapping.WithKeyId(base64.StdEncoding.EncodeToString([]byte(boundaryBenchmarksRootKey))))
	if err != nil {
		return nil, err
	}
	err = wrap.SetAesGcmKeyBytes([]byte(boundaryBenchmarksRootKey))
	if err != nil {
		return nil, err
	}
	return wrap, nil
}

func randStr(n int) string {
	b := make([]byte, n)
	// A rand.Int63() generates 63 random bits, enough for letterIdxMax letters!
	for i, cache, remain := n-1, rand.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = rand.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			b[i] = letterBytes[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	return string(b)
}

// StartUsingTemplate creates a new test database from a postgres template database.
func StartUsingTemplate(dialect string, opt ...Option) (cleanup func() error, retURL, dbname string, err error) {
	if _, ok := supportedDialects[dialect]; !ok {
		return func() error { return nil }, "", "", fmt.Errorf("unsupported dialect: %s", dialect)
	}

	if dialect == "postgres" {
		dialect = "pgx"
	}
	db, err := common.SqlOpen(dialect, fmt.Sprintf("postgres://boundary:boundary@%s:%s/boundary?sslmode=disable", testDBHost, testDBPort))
	if err != nil {
		return func() error { return nil }, "", "", fmt.Errorf("could not connect to source database: %w", err)
	}
	defer db.Close()

	dbname = fmt.Sprintf("boundary_test_%s", randStr(16))
	template := BoundaryTemplate

	opts := GetOpts(opt...)
	if opts.withTemplate != "" {
		template = opts.withTemplate
	}
	if _, ok := supportedTemplates[template]; !ok {
		return func() error { return nil }, "", "", fmt.Errorf("unsupported database template: %s", template)
	}

	_, err = db.Exec(fmt.Sprintf("create database %s template %s", dbname, template))
	if err != nil {
		return func() error { return nil }, "", "", fmt.Errorf("could not create test database: %w", err)
	}

	url := fmt.Sprintf("postgres://boundary:boundary@127.0.0.1:%s/%s?sslmode=disable", testDBPort, dbname)

	cleanup = func() error {
		return dropDatabase(dialect, dbname)
	}

	tdb, err := common.SqlOpen(dialect, url)
	if err != nil {
		return func() error { return nil }, "", "", fmt.Errorf("could not create test database: %w", err)
	}
	defer tdb.Close()

	if err := tdb.Ping(); err != nil {
		return func() error { return nil }, "", "", fmt.Errorf("could not ping test database: %w", err)
	}

	return cleanup, url, dbname, nil
}

const killconns = `
select
  pg_terminate_backend(pg_stat_activity.pid)
from
  pg_stat_activity
where pg_stat_activity.datname = $1
  and pid <> pg_backend_pid();
`

func dropDatabase(dialect, dbname string) error {
	if dbname == "" {
		return fmt.Errorf("empty dbname")
	}

	db, err := common.SqlOpen(dialect, fmt.Sprintf("postgres://boundary:boundary@127.0.0.1:%s/boundary?sslmode=disable", testDBPort))
	if err != nil {
		return err
	}
	defer db.Close()

	_, err = db.Exec(killconns, dbname)
	if err != nil {
		return err
	}
	_, err = db.Exec(fmt.Sprintf("drop database %s", dbname))
	if err != nil {
		return err
	}
	return nil
}
