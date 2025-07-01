// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package mql

import (
	"fmt"
	"strings"
	"unicode"
)

type parser struct {
	l               *lexer
	raw             string
	currentToken    token
	openLogicalExpr stack[struct{}] // something very simple to make sure every logical expr that's opened is closed.
}

func newParser(s string) *parser {
	var fixedUp string
	{
		// remove any leading/trailing whitespace
		fixedUp = strings.TrimSpace(s)
		// remove any leading space before a right parenthesis (issue #42)
		fixedUp = removeSpacesBeforeParen(fixedUp)
	}
	return &parser{
		l:   newLexer(fixedUp),
		raw: s,
	}
}

func (p *parser) parse() (expr, error) {
	const op = "mql.(parser).parse"
	lExpr, err := p.parseLogicalExpr()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	r, err := root(lExpr, p.raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return r, nil
}

// parseLogicalExpr will parse a logicalExpr until an eofToken is reached, which
// may require it to parse a comparisonExpr and/or recursively parse
// logicalExprs
func (p *parser) parseLogicalExpr() (*logicalExpr, error) {
	const op = "parseLogicalExpr"
	logicExpr := &logicalExpr{}

	if err := p.scan(withSkipWhitespace()); err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
TkLoop:
	for p.currentToken.Type != eofToken {
		switch p.currentToken.Type {
		case startLogicalExprToken: // there's a opening paren: (
			// so we've found a new logical expr to parse
			e, err := p.parseLogicalExpr()
			if err != nil {
				return nil, fmt.Errorf("%s: %w", op, err)
			}
			switch {
			// start by assigning the left expr
			case logicExpr.leftExpr == nil:
				logicExpr.leftExpr = e
				break TkLoop
			// we should have a logical operator before the right side expr is assigned
			case logicExpr.logicalOp == "":
				return nil, fmt.Errorf("%s: %w before right side expression in: %q", op, ErrMissingLogicalOp, p.raw)
			// finally, assign the right expr
			case logicExpr.rightExpr == nil:
				if e.rightExpr != nil {
					// if e.rightExpr isn't nil, then we've got a complete
					// expr (left + op + right) and we need to assign this to
					// our rightExpr
					logicExpr.rightExpr = e
					break TkLoop
				}
				// otherwise, we need to assign the left side of e
				logicExpr.rightExpr = e.leftExpr
				break TkLoop
			}
		case stringToken, numberToken, symbolToken:
			if (logicExpr.leftExpr != nil && logicExpr.logicalOp == "") ||
				(logicExpr.leftExpr != nil && logicExpr.rightExpr != nil) {
				return nil, fmt.Errorf("%s: %w starting at %q in: %q", op, ErrUnexpectedExpr, p.currentToken.Value, p.raw)
			}
			cmpExpr, err := p.parseComparisonExpr()
			if err != nil {
				return nil, fmt.Errorf("%s: %w", op, err)
			}
			switch {
			case logicExpr.leftExpr == nil:
				logicExpr.leftExpr = cmpExpr
			case logicExpr.rightExpr == nil:
				logicExpr.rightExpr = cmpExpr
				tmpExpr := &logicalExpr{
					leftExpr:  logicExpr,
					logicalOp: "",
					rightExpr: nil,
				}
				logicExpr = tmpExpr
			default:
				return nil, fmt.Errorf("%s: %w at %q, but both left and right expressions already exist in: %q", op, ErrUnexpectedExpr, p.currentToken.Value, p.raw)
			}
		case endLogicalExprToken:
			if logicExpr.leftExpr == nil {
				return nil, fmt.Errorf("%s: %w %q but we haven't parsed a left side expression in: %q", op, ErrUnexpectedClosingParen, p.currentToken.Value, p.raw)
			}
			return logicExpr, nil
		case andToken, orToken:
			if logicExpr.logicalOp != "" {
				return nil, fmt.Errorf("%s: %w %q when we've already parsed one for expr in: %q", op, ErrUnexpectedLogicalOp, p.currentToken.Value, p.raw)
			}
			o, err := newLogicalOp(p.currentToken.Value)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", op, err)
			}
			logicExpr.logicalOp = o
		default:
			return nil, fmt.Errorf("%s: %w %q in: %q", op, ErrUnexpectedToken, p.currentToken.Value, p.raw)
		}
		if err := p.scan(withSkipWhitespace()); err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
	}
	if p.openLogicalExpr.len() > 0 {
		return nil, fmt.Errorf("%s: %w in: %q", op, ErrMissingClosingParen, p.raw)
	}
	return logicExpr, nil
}

// parseComparisonExpr will parse a comparisonExpr until an eofToken is reached,
// which may require it to parse logicalExpr
func (p *parser) parseComparisonExpr() (expr, error) {
	const op = "mql.(parser).parseComparisonExpr"
	cmpExpr := &comparisonExpr{}

	// our language (and this parser) def requires the tokens to be in the
	// correct order: column, comparisonOp, value. Swapping this order where the
	// value comes first (value, comparisonOp, column) is not supported
	for p.currentToken.Type != eofToken {
		switch {
		case p.currentToken.Type == startLogicalExprToken:
			switch {
			case cmpExpr.isComplete():
				return nil, fmt.Errorf("%s: %w after %s in: %q", op, ErrUnexpectedOpeningParen, cmpExpr, p.raw)
			default:
				return nil, fmt.Errorf("%s: %w in: %q", op, ErrUnexpectedOpeningParen, p.raw)
			}

			// we already have a complete comparisonExpr
		case cmpExpr.isComplete() &&
			(p.currentToken.Type != whitespaceToken && p.currentToken.Type != endLogicalExprToken):
			return nil, fmt.Errorf("%s: %w %s:%q in: %s", op, ErrUnexpectedToken, p.currentToken.Type, p.currentToken.Value, p.raw)

		// we found whitespace, so check if there's a completed logical expr to return
		case p.currentToken.Type == whitespaceToken:
			if cmpExpr.column != "" && cmpExpr.comparisonOp != "" && cmpExpr.value != nil {
				return cmpExpr, nil
			}

		// columns must come first, so handle those conditions
		case cmpExpr.column == "" && p.currentToken.Type != symbolToken:
			// this should be unreachable because parseComparisonExpr(...) is
			// called when a symbolToken is the current token, but I've kept
			// this case here for completeness
			return nil, fmt.Errorf("%s: %w: we expected a %s and got %s == %s in: %q", op, ErrUnexpectedToken, symbolToken, p.currentToken.Type, p.currentToken.Value, p.raw)
		case cmpExpr.column == "": // has to be stringToken representing the column
			cmpExpr.column = p.currentToken.Value

		// after columns, comparison operators must come next
		case cmpExpr.comparisonOp == "":
			c, err := newComparisonOp(p.currentToken.Value)
			if err != nil {
				return nil, fmt.Errorf("%s: %w %q in: %q", op, err, p.currentToken.Value, p.raw)
			}
			cmpExpr.comparisonOp = c

		// finally, values must come at the end
		case cmpExpr.value == nil && (p.currentToken.Type != stringToken && p.currentToken.Type != numberToken && p.currentToken.Type != symbolToken):
			return nil, fmt.Errorf("%s: %w %q in: %q", op, ErrUnexpectedToken, p.currentToken.Value, p.raw)
		case cmpExpr.value == nil:
			switch {
			case p.currentToken.Type == symbolToken:
				return nil, fmt.Errorf("%s: %w %s == %s (expected: %s or %s) in %q", op, ErrInvalidComparisonValueType, p.currentToken.Type, p.currentToken.Value, stringToken, numberToken, p.raw)
			case p.currentToken.Type == stringToken, p.currentToken.Type == numberToken:
				s := p.currentToken.Value
				cmpExpr.value = &s
			default:
				return nil, fmt.Errorf("%s: %w of %s == %s", op, ErrUnexpectedToken, p.currentToken.Type, p.currentToken.Value)
			}
		}
		if err := p.scan(); err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
	}

	switch {
	case cmpExpr.column != "" && cmpExpr.comparisonOp == "":
		return nil, fmt.Errorf("%s: %w in: %q", op, ErrMissingComparisonOp, p.raw)
	default:
		return cmpExpr, nil
	}
}

// scan will get the next token from the lexer. Supported options:
// withSkipWhitespace
func (p *parser) scan(opt ...Option) error {
	const op = "mql.(parser).scan"

	opts, err := getOpts(opt...)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	if p.currentToken, err = p.l.nextToken(); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	if opts.withSkipWhitespace {
		for p.currentToken.Type == whitespaceToken {
			if p.currentToken, err = p.l.nextToken(); err != nil {
				return fmt.Errorf("%s: %w", op, err)
			}
		}
	}

	switch p.currentToken.Type {
	case startLogicalExprToken:
		p.openLogicalExpr.push(struct{}{})
	case endLogicalExprToken:
		p.openLogicalExpr.pop()
	}

	return nil
}

func removeSpacesBeforeParen(s string) string {
	if len(s) == 0 {
		return s
	}
	var result strings.Builder
	runes := []rune(s)
	i := 0
	for i < len(runes) {
		if unicode.IsSpace(runes[i]) {
			start := i
			for i < len(runes) && unicode.IsSpace(runes[i]) {
				i++
			}
			if i < len(runes) && runes[i] == ')' {
				result.WriteRune(')')
				i++ // move past the ')'
			} else {
				// Otherwise, the whitespace is not followed by ')', so keep it
				result.WriteString(string(runes[start:i]))
			}
		} else {
			// Normal character, just append to result
			result.WriteRune(runes[i])
			i++
		}
	}
	return result.String()
}
