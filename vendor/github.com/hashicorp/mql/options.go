// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package mql

import (
	"fmt"
)

type options struct {
	withSkipWhitespace     bool
	withColumnMap          map[string]string
	withColumnFieldTag     string
	withValidateConvertFns map[string]ValidateConvertFunc
	withIgnoredFields      []string
	withPgPlaceholder      bool
	withTableColumnMap     map[string]string // map of model field names to their table.column name
}

// Option - how options are passed as args
type Option func(*options) error

func getDefaultOptions() options {
	return options{
		withColumnMap:          make(map[string]string),
		withColumnFieldTag:     "",
		withValidateConvertFns: make(map[string]ValidateConvertFunc),
		withTableColumnMap:     make(map[string]string),
	}
}

func getOpts(opt ...Option) (options, error) {
	opts := getDefaultOptions()
	for _, o := range opt {
		if err := o(&opts); err != nil {
			return opts, err
		}
	}
	return opts, nil
}

// withSkipWhitespace provides an option to request that whitespace be skipped
func withSkipWhitespace() Option {
	return func(o *options) error {
		o.withSkipWhitespace = true
		return nil
	}
}

// WithColumnMap provides an optional map of columns from the user
// provided query to a field in the given model
func WithColumnMap(m map[string]string) Option {
	const op = "mql.WithColumnMap"
	return func(o *options) error {
		if !isNil(m) {
			if o.withColumnFieldTag != "" {
				return fmt.Errorf("%s: cannot be used with WithColumnFieldTag: %w", op, ErrInvalidParameter)
			}
			o.withColumnMap = m
		}
		return nil
	}
}

// WithColumnFieldTag provides an optional struct tag to use for field mapping
// If a field has this tag, the tag value will be used instead of the field name
func WithColumnFieldTag(tagName string) Option {
	const op = "mql.WithColumnFieldTag"
	return func(o *options) error {
		if tagName == "" {
			return fmt.Errorf("%s: empty tag name: %w", op, ErrInvalidParameter)
		}
		if len(o.withColumnMap) > 0 {
			return fmt.Errorf("%s: cannot be used with WithColumnMap: %w", op, ErrInvalidParameter)
		}
		o.withColumnFieldTag = tagName
		return nil
	}
}

// ValidateConvertFunc validates the value and then converts the columnName,
// comparisonOp and value to a WhereClause
type ValidateConvertFunc func(columnName string, comparisonOp ComparisonOp, value *string) (*WhereClause, error)

// WithConverter provides an optional ConvertFunc for a column identifier in the
// query. This allows you to provide whatever custom validation+conversion you
// need on a per column basis.  See: DefaultValidateConvert(...) for inspiration.
func WithConverter(fieldName string, fn ValidateConvertFunc) Option {
	const op = "mql.WithSqlConverter"
	return func(o *options) error {
		switch {
		case fieldName != "" && !isNil(fn):
			if _, exists := o.withValidateConvertFns[fieldName]; exists {
				return fmt.Errorf("%s: duplicated convert: %w", op, ErrInvalidParameter)
			}
			o.withValidateConvertFns[fieldName] = fn
		case fieldName == "" && !isNil(fn):
			return fmt.Errorf("%s: missing field name: %w", op, ErrInvalidParameter)
		case fieldName != "" && isNil(fn):
			return fmt.Errorf("%s: missing ConvertToSqlFunc: %w", op, ErrInvalidParameter)
		}
		return nil
	}
}

// WithIgnoredFields provides an optional list of fields to ignore in the model
// (your Go struct) when parsing. Note: Field names are case sensitive.
func WithIgnoredFields(fieldName ...string) Option {
	return func(o *options) error {
		o.withIgnoredFields = fieldName
		return nil
	}
}

// WithPgPlaceholders will use parameters placeholders that are compatible with
// the postgres pg driver which requires a placeholder like $1 instead of ?.
// See:
//   - https://pkg.go.dev/github.com/jackc/pgx/v5
//   - https://pkg.go.dev/github.com/lib/pq
func WithPgPlaceholders() Option {
	return func(o *options) error {
		o.withPgPlaceholder = true
		return nil
	}
}

// WithTableColumnMap provides an optional map of columns from the
// model to the table.column name in the generated where clause
//
// For example, if you need to map the language field name to something
// more complex in your SQL statement then you can use this map:
//
//	WithTableColumnMap(map[string]string{"language":"preferences->>'language'"})
//
// In the example above we're mapping "language" field to a json field in
// the "preferences" column. A user can say `language="blah"` and the
// mql-created SQL where clause will contain `preferences->>'language'="blah"`
//
// The field names in the keys to the map should always be lower case.
func WithTableColumnMap(m map[string]string) Option {
	return func(o *options) error {
		if !isNil(m) {
			o.withTableColumnMap = m
		}
		return nil
	}
}
