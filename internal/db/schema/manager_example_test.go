package schema_test

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/boundary/internal/db/common"
	"github.com/hashicorp/boundary/internal/db/schema"
	"github.com/hashicorp/boundary/internal/db/schema/internal/edition"
	"github.com/hashicorp/boundary/internal/db/schema/internal/migration"
	"github.com/hashicorp/boundary/testing/dbtest"
)

func ExampleManager_hooks() {
	ctx := context.Background()
	dialect := dbtest.Postgres

	c, u, _, err := dbtest.StartUsingTemplate(dialect, dbtest.WithTemplate(dbtest.Template1))
	defer c()

	d, err := common.SqlOpen(dialect, u)
	if err != nil {
		log.Fatalf(err.Error())
	}
	editions := edition.Editions{
		{
			Name:    "hooks_example",
			Dialect: schema.Postgres,
			Migrations: migration.Migrations{
				1: migration.Migration{
					Edition: "hooks_example",
					Version: 1,
					Statements: []byte(`
					create table foo (
						id bigint generated always as identity primary key,
						public_id text,
						name text
					);

					-- Not a normal thing to have in a migration
					-- but this is done to but "invalid" data
					-- into a table, that will then have a constraint added
					-- in a future migration.
					insert into foo
						(public_id, name)
					values
						(null, 'Alice'),
						(null, 'Bob'),
						('foo_cathy', 'Cathy');
					`),
				},
				2: migration.Migration{
					Edition: "hooks_example",
					Version: 2,
					Statements: []byte(`
					-- this would fail if data is not updated first
					alter table foo
						alter column public_id
							set not null;
					`),
					PreHook: &migration.Hook{
						CheckFunc: func(ctx context.Context, tx *sql.Tx) error {
							rows, err := tx.QueryContext(
								ctx,
								`select
									id, name
								from foo
								where
									public_id is null`,
							)
							if err != nil {
								return err
							}

							invalid := make([]string, 0)
							for rows.Next() {
								var id int
								var name string
								if err := rows.Scan(&id, &name); err != nil {
									return err
								}
								invalid = append(invalid, fmt.Sprintf("%d:%s", id, name))
							}

							if len(invalid) > 0 {
								return fmt.Errorf("invalid foos:\n%s", strings.Join(invalid, "\n"))
							}
							return nil
						},
						RepairFunc: func(ctx context.Context, tx *sql.Tx) (string, error) {
							rows, err := tx.QueryContext(
								ctx,
								`delete
								from foo
								where
									public_id is null
								returning
									id, name;
								`,
							)
							if err != nil {
								return "", err
							}
							invalid := make([]string, 0)
							for rows.Next() {
								var id int
								var name string
								if err := rows.Scan(&id, &name); err != nil {
									return "", err
								}
								invalid = append(invalid, fmt.Sprintf("%d:%s", id, name))
							}

							if len(invalid) > 0 {
								return fmt.Sprintf("deleted foos:\n%s", strings.Join(invalid, "\n")), nil
							}
							return "", nil
						},
						RepairDescription: "will delete any foo that has a null public_id",
					},
				},
			},
			Priority: 0,
		},
	}

	// Run manager with marking any migrations for repair.
	// The check function in the hook should detect a problem and
	// fail the migration.
	m, err := schema.NewManager(
		ctx,
		schema.Dialect(dialect),
		d,
		schema.WithEditions(editions),
	)
	if err != nil {
		log.Fatalf(err.Error())
	}
	_, err = m.ApplyMigrations(ctx)
	checkErr, _ := err.(schema.MigrationCheckError)
	fmt.Println(checkErr.Error())
	fmt.Printf("repair: %s\n", checkErr.RepairDescription)

	// Now run with the migration marked for repair.
	// The repair function should run, delete data, and the migration
	// will succeed.
	m, err = schema.NewManager(
		ctx,
		schema.Dialect(dialect),
		d,
		schema.WithEditions(editions),
		schema.WithRepairMigrations(schema.RepairMigrations{
			"hooks_example": map[int]bool{
				2: true,
			},
		}),
	)

	logs, err := m.ApplyMigrations(ctx)
	if err != nil {
		log.Fatalf(err.Error())
	}
	for _, log := range logs {
		fmt.Printf("%s:%d: %s\n", log.Edition, log.Version, log.Entry)
	}

	// Output: hooks_example:2: invalid foos:
	// 1:Alice
	// 2:Bob
	// repair: will delete any foo that has a null public_id
	// hooks_example:2: deleted foos:
	// 1:Alice
	// 2:Bob
}
