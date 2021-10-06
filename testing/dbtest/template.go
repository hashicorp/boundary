package dbtest

import (
	"fmt"
	"math/rand"
	"os"
	"time"

	// postgres dialect

	"github.com/hashicorp/boundary/internal/db/common"
	_ "github.com/jackc/pgx/v4/stdlib"
)

var testDBPort = "5432"

// StartUsingTemplate creates a new test database from a postgres template database.
var StartUsingTemplate func(dialect string, opt ...Option) (func() error, string, string, error) = startUsingTemplate

func init() {
	rand.Seed(time.Now().UnixNano())

	p := os.Getenv("TEST_DB_PORT")
	if p != "" {
		testDBPort = p
	}
}

// Dialects
const (
	Postgres = "postgres"
)

// Template Database Names
const (
	BoundaryTemplate = "boundary_template"
	Template1        = "template1"
)

var supportedDialects = map[string]struct{}{
	Postgres: {},
}

var supportedTemplates = map[string]struct{}{
	BoundaryTemplate: {},
	Template1:        {},
}

const letterBytes = "abcdefghijklmnopqrstuvwxyz"
const (
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
)

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

func startUsingTemplate(dialect string, opt ...Option) (cleanup func() error, retURL, dbname string, err error) {
	if _, ok := supportedDialects[dialect]; !ok {
		return func() error { return nil }, "", "", fmt.Errorf("unsupported dialect: %s", dialect)
	}

	if dialect == "postgres" {
		dialect = "pgx"
	}
	db, err := common.SqlOpen(dialect, fmt.Sprintf("postgres://boundary:boundary@127.0.0.1:%s/boundary?sslmode=disable", testDBPort))
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
