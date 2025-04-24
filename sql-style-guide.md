# SQL Style Guide

This guide establishes the standards for SQL in Boundary.

## Purpose

These guidelines are designed to make our SQL more readable, maintainable, and greppable.

## Rules

### Formatting

- No tabs. 2 spaces per indent.
- No trailing whitespace.
- No more than two blank lines between statements.
- No empty lines in the middle of a single statement.
- Do not SHOUTCASE or "Sentence case" SQL keywords (e.g., use `select`, not `SELECT` or `Select`).
- Use "river" formatting for [DML](#data-manipulation-statements).

### Data Definition Statements

Keep the object of `create`, `alter`, `drop`, and `comment on` statements on the
same line as the statement.

### Tables

```sql
create table imaginary_basket (
  public_id wt_public_id primary key,
  store_id wt_public_id not null
    constraint imaginary_store_fkey
      references imaginary_store (public_id)
      on delete cascade
      on update cascade,
  basket_name text not null
    constraint basket_name_must_not_be_empty
      check(
        length(trim(basket_name)) > 0
      ),
  basket_type text not null default 'fruit_basket'
    constraint basket_type_enm_fkey
      references basket_type_enm (name)
      on delete restrict
      on update cascade,
  constraint imaginary_basket_store_id_basket_name_uq
    unique(store_id, basket_name)
);
comment on table imaginary_basket is
  'imaginary_basket is a table where each row is a resource that represents an imaginary shopping basket.';
```

For `create table` statements:

- Keep the `create table` statement and the name of the table on the same line.
- For columns, keep the column name, column type, `not null` (if applicable),
  and default value (if applicable) on the same line.
- Put the `primary key` declaration at the start of the `create table` statement.
- If the `primary key` is a single column, put the `primary key` declaration on
  the same line as the column name and column type.
- Put constraints for a single column on a new line indented under the column declaration.

**Constraints**:
- Name all constraints.
- Give `check` constraints a name that describes what rule the constraint is enforcing.
- The naming pattern for foreign key constraints is `reftable_fkey` where
  `reftable` is the name of the referenced table.
- The naming pattern for unique constraints is `tablename_col1_colx_uq` where
  `tablename` is the name of the table and `col1_colx` is the name of each
  column in the unique constraint.
- The naming pattern for unique constraint names which would be over 63 characters
  in length is to prioritize keeping the full `tablename_uq` pattern intact and
  abbreviate the names of the columns.

### Functions

```sql
create or replace function colorize_basket(basket_id wt_public_id, basket_color text) returns void
as $$
begin
  ....
end;
$$ language plpgsql;
comment on function colorize_basket is
  'colorize_basket is a function ....';
```

For `create function` and `create or replace function` statements:

- Keep the `create function` statement, function name, function parameters and `returns` statement on the same line.

### Triggers

```sql
create trigger update_version_column after update of version, termination_reason, key_id, tofu_token, server_id, server_type on session
  for each row execute procedure update_version_column();
```

For `create trigger` statements:
- Keep the `create trigger` statement, trigger name, `before | after`, event
  name, and `on table_name` statement on the same line.
- Put the remaining statements on a new indented line.

### Domains

```sql
create domain wt_private_id as text not null
check(
  length(trim(value)) > 10
);
comment on domain wt_private_id is
  'Random ID generated with github.com/hashicorp/go-secure-stdlib/base62';
```

For `create domain` statements:
- Keep the `create domain` statement, domain name, `as data_type`, `not null`
  (if applicable), and default value (if applicable) on the same line.
- Put check constraints on new lines.

### `comment on` statements

For `comment on` statements:

- Keep the `comment on` statement, object type, object name, and `is`
  statement on the same line.
- Put `comment on` statements directly below the database object the comment is on.
- Do not put any blank lines between the `comment on` statement and the database
  object declaration block that comment is for.
- Put the text of the `comment on` a new indented line.

### Data Manipulation Statements

Data manipulation statements should align SQL keywords in a column to form a
[river](https://en.wikipedia.org/wiki/River_(typography))
between the keywords and the rest of the statement.
This makes it easier to scan the statement.
It can also help identify keywords in cases where syntax
highlighting might not be available,
such as when statements are written in go string literals.

```sql
   select b.public_id,
          b.basket_name,
          b.basket_type,
          s.store_name,
          s.store_descrption
     from imaginary_basket as b
left join imaginary_store  as s
       on b.store_id = s.public_id
    where basket_type = $1;
```

```sql
update imaginary_basket
   set basket_name = basket_name || '(' || basket_type || ')'
 where basket_type = $1;
```

```sql
delete
  from imaginary_basket
 where basket_type = $1;
```

For insert statements, align the spacing of the column names and values.

```sql
insert into imaginary_basket
            (public_id,     store_id,      basket_type,    basket_name)
     values ('b_123456789', 's_123456789', 'fruit_basket', 'my fruit basket'),
            ('b_234567891', 's_123456789', 'toy_basket',   'my toy basket');
```

For more complex queries,
there can be multiple rivers,
like when a query includes sub-queries,
or when using a common table expression (CTE):

```sql
with baskets as (
  select public_id
    from basket
   where (create_time, public_id) < ($1, $2)
order by create_time desc,
         public_id   desc
   limit 1000
),
imaginary_baskets as (
  select *
    from imaginary_basket
   where public_id in (select public_id
                         from baskets)
),
real_baskets as (
  select *
    from real_basket
   where public_id in (select public_id
                         from baskets)
),
final as (
   select public_id,
          basket_name,
          basket_type,
          'imaginary' as type
     from imaginary_baskets
    union
   select public_id,
          basket_name,
          basket_type,
          'real' as type
     from real_baskets
)
  select *
    from final
order by create_time desc,
         public_id   desc;
```
