// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package template

import (
	"context"
	"strings"
	"text/template"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/util"
)

// Parsed contains information about a template parsed via New. Technically
// `raw` and `funcMap` are not required to be cached here as they are part of
// the `template.Template` object but it is useful for tests.
type Parsed struct {
	raw     string
	tmpl    *template.Template
	funcMap template.FuncMap
}

// New creates a Parsed struct. It requires the raw string.
func New(ctx context.Context, raw string) (*Parsed, error) {
	const op = "util.template.New"

	if raw == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "empty raw template")
	}

	ret := &Parsed{
		raw: raw,
		funcMap: map[string]any{
			"truncateFrom": truncateFrom,
			"coalesce":     coalesce,
		},
	}

	tmpl, err := template.New("template").
		Funcs(ret.funcMap).
		Parse(ret.raw)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("error parsing template"))
	}
	ret.tmpl = tmpl

	return ret, nil
}

// Generate based on the provided template
func (p *Parsed) Generate(ctx context.Context, data any) (string, error) {
	const op = "util.template.(Parsed).Generate"

	switch {
	case p.tmpl == nil:
		return "", errors.New(ctx, errors.InvalidParameter, op, "parsed template not initialized")
	case util.IsNil(data):
		return "", errors.New(ctx, errors.InvalidParameter, op, "input data is nil")
	}

	str := &strings.Builder{}
	if err := p.tmpl.Execute(str, data); err != nil {
		return "", errors.Wrap(ctx, err, op, errors.WithMsg("error executing template"))
	}

	out := str.String()
	if strings.Contains(out, "<nil>") {
		return "", errors.New(ctx, errors.InvalidParameter, op, "template execution resulted in nil value")
	}

	return out, nil
}
