package _0

import (
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDomain_SentinelMigration(t *testing.T) {
	const (
		createTable = `
create table if not exists test_table_wt_sentinel (
  name text primary key,
  sentinel wt_sentinel
);
`
		insert = `
insert into test_table_wt_sentinel(name, sentinel)
values ($1, $2);
`

		search = `
select sentinel 
  from test_table_wt_sentinel 
 where name = $1;
`

		migration = `
begin;

update test_table_wt_sentinel
  set sentinel = concat(sentinel, u&'\ffff')
  where wt_is_sentinel(sentinel)
    and not starts_with(reverse(sentinel), u&'\ffff');

alter domain wt_sentinel
    drop constraint wt_sentinel_not_valid;

drop function wt_is_sentinel;

create function wt_is_sentinel(string text)
    returns bool
as $$
select starts_with(string, u&'\fffe') and starts_with(reverse(string), u&'\ffff');
$$ language sql
    immutable
    returns null on null input;
comment on function wt_is_sentinel is
    'wt_is_sentinel returns true if string is a sentinel value';

alter domain wt_sentinel
    add constraint wt_sentinel_not_valid
        check(
                wt_is_sentinel(value)
                or
                length(trim(trailing u&'\ffff' from trim(leading u&'\fffe ' from value))) > 0
            );

comment on domain wt_sentinel is
    'A non-empty string with a Unicode prefix of U+FFFE and suffix of U+FFFF to indicate it is a sentinel value';

commit;
`
	)

	conn, _ := db.TestSetup(t, "postgres")
	db := conn.DB()

	if _, err := db.Exec(createTable); err != nil {
		t.Fatalf("query: \n%s\n error: %s", createTable, err)
	}

	tests := []struct {
		name            string
		beforeMigration string
		afterMigration  string
	}{
		{"normal", "\ufffefoo", "\ufffefoo\uffff"},
		{"normal non-sentinel", "foo", "foo"},
		{"already has end sentinel", "\ufffefoo\uffff", "\ufffefoo\uffff"},
		{"trailing sentinel", "\ufffefoo\ufffe", "\ufffefoo\ufffe\uffff"},
		{"sentinel with space before word", "\ufffe foo\uffff", "\ufffe foo\uffff"},
		{"sentinel with space after word", "\ufffefoo \uffff", "\ufffefoo \uffff"},
		{"multiple sentinels", "\ufffe\ufffefoo\uffff\uffff", "\ufffe\ufffefoo\uffff\uffff"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			t.Logf("insert value: %q", tt.beforeMigration)
			_, err := db.Query(insert, tt.name, tt.beforeMigration)
			assert.NoError(err)
		})
	}

	// Run migration
	if _, err := db.Exec(migration); err != nil {
		t.Fatalf("query: \n%s\n error: %s", createTable, err)
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			require, assert := require.New(t), assert.New(t)

			var sentinel string
			err := db.QueryRow(search, tt.name).Scan(&sentinel)
			require.NoError(err)
			assert.Equal(tt.afterMigration, sentinel)
		})
	}
}
