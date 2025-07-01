// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package mql

import (
	"fmt"
	"reflect"
	"strings"
)

// WhereClause contains a SQL where clause condition and its arguments.
type WhereClause struct {
	// Condition is the where clause condition
	Condition string
	// Args for the where clause condition
	Args []any
}

// Parse will parse the query and use the provided database model to create a
// where clause. Supported options: WithColumnMap, WithIgnoreFields,
// WithConverter, WithPgPlaceholder
func Parse(query string, model any, opt ...Option) (*WhereClause, error) {
	const op = "mql.Parse"
	switch {
	case query == "":
		return nil, fmt.Errorf("%s: missing query: %w", op, ErrInvalidParameter)
	case isNil(model):
		return nil, fmt.Errorf("%s: missing model: %w", op, ErrInvalidParameter)
	}
	p := newParser(query)
	expr, err := p.parse()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	fValidators, err := fieldValidators(reflect.ValueOf(model), opt...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	e, err := exprToWhereClause(expr, fValidators, opt...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	opts, err := getOpts(opt...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	if opts.withPgPlaceholder {
		for i := 0; i < len(e.Args); i++ {
			placeholder := fmt.Sprintf("$%d", i+1)
			e.Condition = strings.Replace(e.Condition, "?", placeholder, 1)
		}
	}
	return e, nil
}

// exprToWhereClause generates the where clause condition along with its
// required arguments. Supported options: WithColumnMap, WithConverter
func exprToWhereClause(e expr, fValidators map[string]validator, opt ...Option) (*WhereClause, error) {
	const op = "mql.exprToWhereClause"
	switch {
	case isNil(e):
		return nil, fmt.Errorf("%s: missing expression: %w", op, ErrInvalidParameter)
	case isNil(fValidators):
		return nil, fmt.Errorf("%s: missing validators: %w", op, ErrInvalidParameter)
	}

	switch v := e.(type) {
	case *comparisonExpr:
		opts, err := getOpts(opt...)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
		switch validateConvertFn, ok := opts.withValidateConvertFns[v.column]; {
		case ok && !isNil(validateConvertFn):
			return validateConvertFn(v.column, v.comparisonOp, v.value)
		default:
			var ok bool
			var validator validator
			columnName := v.column
			switch {
			case opts.withColumnFieldTag != "":
				validator, ok = fValidators[columnName]
			default:
				columnName = strings.ToLower(v.column)
				if n, ok := opts.withColumnMap[columnName]; ok {
					columnName = n
				}

				validator, ok = fValidators[strings.ToLower(strings.ReplaceAll(columnName, "_", ""))]
			}

			if !ok {
				cols := make([]string, len(fValidators))
				for c := range fValidators {
					cols = append(cols, c)
				}

				return nil, fmt.Errorf("%s: %w %q %s", op, ErrInvalidColumn, columnName, cols)
			}

			w, err := defaultValidateConvert(columnName, v.comparisonOp, v.value, validator, opt...)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", op, err)
			}
			return w, nil
		}
	case *logicalExpr:
		left, err := exprToWhereClause(v.leftExpr, fValidators, opt...)
		if err != nil {
			return nil, fmt.Errorf("%s: invalid left expr: %w", op, err)
		}
		if v.logicalOp == "" {
			return nil, fmt.Errorf("%s: %w that stated with left expr condition: %q args: %q", op, ErrMissingLogicalOp, left.Condition, left.Args)
		}
		right, err := exprToWhereClause(v.rightExpr, fValidators, opt...)
		if err != nil {
			return nil, fmt.Errorf("%s: invalid right expr: %w", op, err)
		}
		return &WhereClause{
			Condition: fmt.Sprintf("(%s %s %s)", left.Condition, v.logicalOp, right.Condition),
			Args:      append(left.Args, right.Args...),
		}, nil
	default:
		return nil, fmt.Errorf("%s: unexpected expr type %T: %w", op, v, ErrInternal)
	}
}
