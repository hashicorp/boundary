package database

import (
	"database/sql"
	"log"
	"testing"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/jackc/pgx/v4"
)

func TestCleanMigrations(t *testing.T) {
	const (
		listTables = `
select tablename
from pg_catalog.pg_tables
where schemaname != 'pg_catalog'
and schemaname != 'information_schema'
and tablename != 'schema_migrations';
`

		listDomains = `
select t.typname
from pg_catalog.pg_type as t
inner join pg_catalog.pg_namespace as ns on t.typnamespace = ns.oid
where t.typtype = 'd'
and ns.nspname = 'public';
`
	)

	cleanup, connURL := newPostgresTestContainer(t)
	defer cleanup()

	db, err := sql.Open("postgres", connURL)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	m, err := migrate.New("file://migrations/postgresql", connURL)
	if err != nil {
		t.Fatalf("Error creating migrations: %s", err)
	}
	if err := m.Up(); err != nil {
		t.Fatalf("Error running migrations Up: %s", err)
	}
	if err := m.Down(); err != nil {
		t.Fatalf("Error running migrations Down: %s", err)
	}

	if n := fetchNames(t, db, listDomains); len(n) > 0 {
		t.Errorf("want no domains, got %v", n)
	}

	if n := fetchNames(t, db, listTables); len(n) > 0 {
		t.Errorf("want no tables, got %v", n)
	}
}

func fetchNames(t *testing.T, db *sql.DB, query string) []string {
	t.Helper()
	rows, err := db.Query(query)
	if err != nil {
		t.Fatalf("query: \n%s\n error: %s", query, err)
	}
	defer rows.Close()

	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("query: \n%s\n scan error: %s", query, err)
		}
		names = append(names, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("query: \n%s\n rows error: %s", query, err)
	}
	return names
}
