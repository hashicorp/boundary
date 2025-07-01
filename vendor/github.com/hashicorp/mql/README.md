# MQL
[![Go
Reference](https://pkg.go.dev/badge/github.com/hashicorp/mql/mql.svg)](https://pkg.go.dev/github.com/hashicorp/mql)
[![Go Report
Card](https://goreportcard.com/badge/github.com/hashicorp/mql)](https://goreportcard.com/report/github.com/hashicorp/mql)
[![Go Coverage](https://raw.githack.com/hashicorp/mql/main/coverage/coverage.svg)](https://raw.githack.com/hashicorp/mql/main/coverage/coverage.html)

The [mql](https://pkg.go.dev/github.com/hashicorp/mql) (Model Query Language) Go package provides a language that end users can use to query your
database models, without them having to learn SQL or exposing your
application to SQL injection.

## Examples

### [github.com/go-gorm/gorm](https://github.com/go-gorm/gorm)

```Go
w, err := mql.Parse(`name="alice" or name="bob"`,User{})
if err != nil {
  return nil, err
}
err = db.Where(w.Condition, w.Args...).Find(&users).Error
```

### [database/sql](https://pkg.go.dev/database/sql)

```Go
w, err := mql.Parse(`name="alice" or name="bob"`,User{}, mql.WithPgPlaceholders())
if err != nil {
  return nil, err
}
q := fmt.Sprintf("select * from users where %s", w.Condition)
rows, err := db.Query(q, w.Args...)
```

### [github.com/hashicorp/go-dbw](https://github.com/hashicorp/go-dbw)

```Go
w, err := mql.Parse(`name="alice" or name="bob")`,User{})
if err != nil {
  return nil, err
}
err := rw.SearchWhere(ctx, &users, w.Condition, w.Args)
```

## Some bits about usage

First, you define a model you wish to query as a Go `struct` and then provide a [mql]((https://pkg.go.dev/badge/github.com/hashicorp/mql/mql.svg))
query. The package then uses the query along with a model to generate a
parameterized SQL where clause.

Fields in your model can be compared with the following operators: `=`, `!=`,
`>=`, `<=`, `<`, `>`, `%` .

Strings must be quoted. Double quotes `"`, single quotes `'` or backticks ``
` `` can be used as delimiters.  Users can choose whichever supported delimiter
makes it easier to quote their string.

Comparison operators can have optional leading/trailing whitespace.

The `%` operator allows you to do partial string matching using LIKE "%value%". This
matching is case insensitive.

The `=` equality operator is case insensitive when used with string fields.

Comparisons can be combined using: `and`, `or`.

More complex queries can be created using parentheses.

See [GRAMMAR.md](./GRAMMAR.md) for a more complete documentation of [mql](https://pkg.go.dev/github.com/hashicorp/mql)'s grammar.

Example query:

`name="alice" and age > 11 and (region % 'Boston' or region="south shore")`

### Date/Time fields

If your model contains a time.Time field, then we'll append `::date` to the
column name when generating a where clause and the comparison value must be in
an `ISO-8601` format.

Note: It's possible to compare date-time fields down to the
millisecond using `::date` and a literal in `ISO-8601` format.

Currently, this is the only supported way to compare
dates, if you need something different then you'll need to provide your own
custom validator/converter via
[WithConverter(...)](https://pkg.go.dev/github.com/hashicorp/mql#WithConverter)
when calling
[mql.Parse(...)](https://pkg.go.dev/github.com/hashicorp/mql#Parse).

We provide default validation+conversion of fields in a model when parsing
and generating a
[WhereClause](https://pkg.go.dev/github.com/hashicorp/mql#WhereClause).  You can
provide optional validation+conversion functions for fields in your model via
[WithConverter(...)](https://pkg.go.dev/github.com/hashicorp/mql#WithConverter).

Example date comparison down to the HH::MM using an ISO-8601 format:

`name="alice" and created_at>"2023-12-01 14:01"`

Note: Expressions with the same level of precedence are evaluated right to left.
Example:
`name="alice" and age > 11 and region =
"Boston"` is evaluated as: `name="alice" and (age > 11 and region =
"Boston")`



### Mapping field names

You can also provide an optional map from query column identifiers to model
field names via
[WithColumnMap(...)](https://pkg.go.dev/github.com/hashicorp/mql#WithColumnMap)
if needed.

Example
[WithColumnMap(...)](https://pkg.go.dev/github.com/hashicorp/mql#WithColumnMap)
usage:

``` Go
type User struct {
    FullName string
}

// map the column alice to field name FullName
columnMap := map[string]string{
    "name": "FullName",
}

w, err := mql.Parse(
    `name="alice"`,
    User{},
    mql.WithColumnMap(columnMap))

if err != nil {
    return nil, err
}
```

### Mapping via struct tags

You can use struct tags to map model fields to column names by using
[WithColumnFieldTag(...)](https://pkg.go.dev/github.com/hashicorp/mql#WithColumnFieldTag).
This allows you to define the mapping in your struct definition rather than at query time.

Example
[WithColumnFieldTag(...)](https://pkg.go.dev/github.com/hashicorp/mql#WithColumnFieldTag)
usage:

``` Go
type User struct {
    Name string `db:"full_name"`
}

w, err := mql.Parse(
    `Name="alice"`,
    User{},
    mql.WithColumnFieldTag("db"))

if err != nil {
    return nil, err
}

fmt.Print(w.Condition) // prints full_name=?
```

### Mapping output column names

You can also provide an optional map from model field names to output column
names via
[WithTableColumnMap(...)](https://pkg.go.dev/github.com/hashicorp/mql#WithTableColumnMap)
if needed.

Example
[WithTableColumnMap(...)](https://pkg.go.dev/github.com/hashicorp/mql#WithTableColumnMap)
usage:

``` Go
type User struct {
    FullName string
}

// map the field name FullName to column "u.fullname"
tableColumnMap := map[string]string{
    "fullname": "u.fullname",
}

w, err := mql.Parse(
    `FullName="alice"`,
    User{},
    mql.WithTableColumnMap(tableColumnMap))

if err != nil {
    return nil, err
}

fmt.Print(w.Condition) // prints u.fullname=?
```

### Ignoring fields

If your model (Go struct) has fields you don't want users searching then you can
optionally provide a list of columns to be ignored via [WithIgnoreFields(...)](https://pkg.go.dev/github.com/hashicorp/mql#WithIgnoreFields)

Example
[WithIgnoreFields(...)](https://pkg.go.dev/github.com/hashicorp/mql#WithIgnoreFields)
usage:

```Go
type User {
    Name string
    CreatedAt time.Time
    UpdatedAt time.Time
}

// you want to keep users from using queries that include the user fields
// of: created_at updated_at
w, err := mql.Parse(
    `name="alice"`,
    User{},
    mql.WithIgnoreFields("CreatedAt", "UpdatedAt"))

if err != nil {
    return nil, err
}
```

### Custom converters/validators

Sometimes the default out-of-the-box bits doesn't fit your needs.  If you need to
override how expressions (column name, operator and value) is converted and
validated during the generation of a
[WhereClause](https://pkg.go.dev/github.com/hashicorp/mql#WhereClause), then
you can optionally
provide your own validator/convertor via
[WithConverter(...)](https://pkg.go.dev/github.com/hashicorp/mql#WithConverter)

Example
[WithConverter(...)](https://pkg.go.dev/github.com/hashicorp/mql#WithConverter)
usage:

``` Go
// define a converter for mySQL dates
mySQLDateConverter := func(columnName string, comparisonOp mql.ComparisonOp, value *string) (*mql.WhereClause, error) {
  // you should add some validation of function parameters here.
  return &mql.WhereClause{
    Condition: fmt.Sprintf("%s%sSTR_TO_DATE(?)", columnName, comparisonOp),
    Args:      []any{*value},
  }, nil
}

w, err := mql.Parse(
    `name="alice" and created_at > "2023-06-18"`,
    User{},
    mql.WithConverter("CreatedAt", mySqlDateConverter))

if err != nil {
    return nil, err
}

```

### Grammar

See: [GRAMMAR.md](./GRAMMAR.md)


## Security

**Please note**: We take security and our users' trust very seriously. If you
believe you have found a security issue, please *[responsibly
disclose](https://www.hashicorp.com/security#vulnerability-reporting)* by
contacting us at  security@hashicorp.com.
## Contributing

Thank you for your interest in contributing! Please refer to
[CONTRIBUTING.md](https://github.com/hashicorp/mql/blob/main/CONTRIBUTING.md)
for guidance.
