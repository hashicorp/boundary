// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package mql

import (
	"fmt"
)

type exprType int

const (
	unknownExprType exprType = iota
	comparisonExprType
	logicalExprType
)

type expr interface {
	Type() exprType
	String() string
}

// ComparisonOp defines a set of comparison operators
type ComparisonOp string

const (
	GreaterThanOp        ComparisonOp = ">"
	GreaterThanOrEqualOp ComparisonOp = ">="
	LessThanOp           ComparisonOp = "<"
	LessThanOrEqualOp    ComparisonOp = "<="
	EqualOp              ComparisonOp = "="
	NotEqualOp           ComparisonOp = "!="
	ContainsOp           ComparisonOp = "%"
)

func newComparisonOp(s string) (ComparisonOp, error) {
	const op = "newComparisonOp"
	switch ComparisonOp(s) {
	case
		GreaterThanOp,
		GreaterThanOrEqualOp,
		LessThanOp,
		LessThanOrEqualOp,
		EqualOp,
		NotEqualOp,
		ContainsOp:
		return ComparisonOp(s), nil
	default:
		return "", fmt.Errorf("%s: %w %q", op, ErrInvalidComparisonOp, s)
	}
}

type comparisonExpr struct {
	column       string
	comparisonOp ComparisonOp
	value        *string
}

// Type returns the expr type
func (e *comparisonExpr) Type() exprType {
	return comparisonExprType
}

// String returns a string rep of the expr
func (e *comparisonExpr) String() string {
	switch e.value {
	case nil:
		return fmt.Sprintf("(comparisonExpr: %s %s nil)", e.column, e.comparisonOp)
	default:
		return fmt.Sprintf("(comparisonExpr: %s %s %s)", e.column, e.comparisonOp, *e.value)
	}
}

func (e *comparisonExpr) isComplete() bool {
	return e.column != "" && e.comparisonOp != "" && e.value != nil
}

// defaultValidateConvert will validate the comparison expr value, and then convert the
// expr to its SQL equivalence.
func defaultValidateConvert(columnName string, comparisonOp ComparisonOp, columnValue *string, validator validator, opt ...Option) (*WhereClause, error) {
	const op = "mql.(comparisonExpr).convertToSql"
	switch {
	case columnName == "":
		return nil, fmt.Errorf("%s: %w", op, ErrMissingColumn)
	case comparisonOp == "":
		return nil, fmt.Errorf("%s: %w", op, ErrMissingComparisonOp)
	case isNil(columnValue):
		return nil, fmt.Errorf("%s: %w", op, ErrMissingComparisonValue)
	case validator.fn == nil:
		return nil, fmt.Errorf("%s: missing validator function: %w", op, ErrInvalidParameter)
	case validator.typ == "":
		return nil, fmt.Errorf("%s: missing validator type: %w", op, ErrInvalidParameter)
	}

	// everything was validated at the start, so we know this is a valid/complete comparisonExpr
	e := &comparisonExpr{
		column:       columnName,
		comparisonOp: comparisonOp,
		value:        columnValue,
	}

	v, err := validator.fn(*e.value)
	if err != nil {
		return nil, fmt.Errorf("%s: %q in %s: %w", op, *e.value, e.String(), ErrInvalidParameter)
	}

	opts, err := getOpts(opt...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	if n, ok := opts.withTableColumnMap[columnName]; ok {
		// override our column name with the mapped column name
		columnName = n
	}

	if validator.typ == "time" {
		columnName = fmt.Sprintf("%s::date", columnName)
	}
	switch e.comparisonOp {
	case ContainsOp:
		return &WhereClause{
			Condition: fmt.Sprintf("%s like ?", columnName),
			Args:      []any{fmt.Sprintf("%%%s%%", v)},
		}, nil
	default:
		return &WhereClause{
			Condition: fmt.Sprintf("%s%s?", columnName, e.comparisonOp),
			Args:      []any{v},
		}, nil
	}
}

type logicalOp string

const (
	andOp logicalOp = "and"
	orOp  logicalOp = "or"
)

func newLogicalOp(s string) (logicalOp, error) {
	const op = "newLogicalOp"
	switch logicalOp(s) {
	case andOp, orOp:
		return logicalOp(s), nil
	default:
		return "", fmt.Errorf("%s: %w %q", op, ErrInvalidLogicalOp, s)
	}
}

type logicalExpr struct {
	leftExpr  expr
	logicalOp logicalOp
	rightExpr expr
}

// Type returns the expr type
func (l *logicalExpr) Type() exprType {
	return logicalExprType
}

// String returns a string rep of the expr
func (l *logicalExpr) String() string {
	return fmt.Sprintf("(logicalExpr: %s %s %s)", l.leftExpr, l.logicalOp, l.rightExpr)
}

// root will return the root of the expr tree
func root(lExpr *logicalExpr, raw string) (expr, error) {
	const op = "mql.root"
	switch {
	// intentionally not checking raw, since can be an empty string
	case lExpr == nil:
		return nil, fmt.Errorf("%s: %w (missing expression)", op, ErrInvalidParameter)
	}
	logicalOp := lExpr.logicalOp
	if logicalOp != "" && lExpr.rightExpr == nil {
		return nil, fmt.Errorf("%s: %w in: %q", op, ErrMissingRightSideExpr, raw)
	}

	for lExpr.logicalOp == "" {
		switch {
		case lExpr.leftExpr == nil:
			return nil, fmt.Errorf("%s: %w nil in: %q", op, ErrMissingExpr, raw)
		case lExpr.leftExpr.Type() == comparisonExprType:
			return lExpr.leftExpr, nil
		default:
			lExpr = lExpr.leftExpr.(*logicalExpr)
		}
	}
	return lExpr, nil
}
