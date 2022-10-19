package template

import (
	"context"
	"strings"
	"text/template"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/util"
)

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
		funcMap: map[string]interface{}{
			"truncateFrom": truncateFrom,
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
func (p *Parsed) Generate(ctx context.Context, data interface{}) (string, error) {
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

	return str.String(), nil
}
