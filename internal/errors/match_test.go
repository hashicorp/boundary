package errors

import (
	stderrors "errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestT(t *testing.T) {
	t.Parallel()
	stdErr := stderrors.New("test error")
	tests := []struct {
		name string
		args []interface{}
		want *Template
	}{
		{
			name: "all fields",
			args: []interface{}{
				"test error msg",
				Op("alice.Bob"),
				InvalidParameter,
				stdErr,
				Integrity,
			},
			want: &Template{
				Err: Err{
					Code:    InvalidParameter,
					Msg:     "test error msg",
					Op:      "alice.Bob",
					Wrapped: stdErr,
				},
				Kind: Integrity,
			},
		},
		{
			name: "Kind only",
			args: []interface{}{
				Integrity,
			},
			want: &Template{
				Kind: Integrity,
			},
		},
		{
			name: "multiple Kinds",
			args: []interface{}{
				Search,
				Integrity,
			},
			want: &Template{
				Kind: Integrity,
			},
		},
		{
			name: "ignore",
			args: []interface{}{
				32,
			},
			want: &Template{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			got := T(tt.args...)
			assert.Equal(tt.want, got)
		})
	}
}

func TestTemplate_Info(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		template *Template
		want     Info
	}{
		{
			name:     "nil",
			template: nil,
			want:     errorCodeInfo[Unknown],
		},
		{
			name:     "Code",
			template: T(InvalidParameter),
			want:     errorCodeInfo[InvalidParameter],
		},
		{
			name:     "Code and Kind",
			template: T(InvalidParameter, Integrity),
			want:     errorCodeInfo[InvalidParameter],
		},
		{
			name:     "Kind without Code",
			template: T(Integrity),
			want:     Info{Kind: Integrity, Message: "Unknown"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			assert.Equal(tt.want, tt.template.Info())
		})
	}
}

func TestTemplate_Error(t *testing.T) {
	t.Parallel()
	stdErr := stderrors.New("test error")
	tests := []struct {
		name     string
		template *Template
	}{
		{
			name:     "Kind only",
			template: T(Integrity),
		},
		{
			name: "all params",
			template: T(
				"test error msg",
				Op("alice.Bob"),
				InvalidParameter,
				stdErr,
				Integrity,
			),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			got := tt.template.Error()
			assert.Equal("Template error", got)
		})
	}
}

func TestMatch(t *testing.T) {
	t.Parallel()
	stdErr := stderrors.New("test error")
	tests := []struct {
		name     string
		template *Template
		err      error
		want     bool
	}{
		{
			name:     "nil template",
			template: nil,
			err:      E(WithCode(NotUnique), WithMsg("this thing was must be unique")),
			want:     false,
		},
		{
			name:     "nil err",
			template: T(Integrity),
			err:      nil,
			want:     false,
		},
		{
			name:     "match on Kind only",
			template: T(Integrity),
			err: E(
				WithCode(NotUnique),
				WithMsg("this thing must be unique"),
				WithOp("alice.Bob"),
				WithWrap(ErrInvalidFieldMask),
			),
			want: true,
		},
		{
			name:     "no match on Kind only",
			template: T(Integrity),
			err: E(
				WithCode(RecordNotFound),
				WithMsg("this thing is missing"),
				WithOp("alice.Bob"),
				WithWrap(ErrInvalidFieldMask),
			),
			want: false,
		},
		{
			name:     "match on Code only",
			template: T(NotUnique),
			err: E(
				WithCode(NotUnique),
				WithMsg("this thing must be unique"),
				WithOp("alice.Bob"),
				WithWrap(ErrInvalidFieldMask),
			),
			want: true,
		},
		{
			name:     "no match on Code only",
			template: T(NotUnique),
			err: E(
				WithCode(RecordNotFound),
				WithMsg("this thing is missing"),
				WithOp("alice.Bob"),
				WithWrap(ErrInvalidFieldMask),
			),
			want: false,
		},
		{
			name:     "match on Op only",
			template: T(Op("alice.Bob")),
			err: E(
				WithCode(NotUnique),
				WithMsg("this thing must be unique"),
				WithOp("alice.Bob"),
				WithWrap(ErrInvalidFieldMask),
			),
			want: true,
		},
		{
			name:     "no match on Op only",
			template: T(Op("alice.Alice")),
			err: E(
				WithCode(RecordNotFound),
				WithMsg("this thing is missing"),
				WithOp("alice.Bob"),
				WithWrap(ErrInvalidFieldMask),
			),
			want: false,
		},
		{
			name: "match on everything",
			template: T(
				"this thing must be unique",
				Integrity,
				InvalidParameter,
				ErrInvalidFieldMask,
				Op("alice.Bob"),
			),
			err: E(
				WithCode(InvalidParameter),
				WithMsg("this thing must be unique"),
				WithOp("alice.Bob"),
				WithWrap(ErrInvalidFieldMask),
			),
			want: true,
		},
		{
			name:     "match on Wrapped only",
			template: T(ErrInvalidFieldMask),
			err: E(
				WithCode(NotUnique),
				WithMsg("this thing must be unique"),
				WithOp("alice.Bob"),
				WithWrap(ErrInvalidFieldMask),
			),
			want: true,
		},
		{
			name:     "no match on Wrapped only",
			template: T(ErrNotUnique),
			err: E(
				WithCode(RecordNotFound),
				WithMsg("this thing is missing"),
				WithOp("alice.Bob"),
				WithWrap(ErrInvalidFieldMask),
			),
			want: false,
		},
		{
			name:     "match on Wrapped only stderror",
			template: T(stdErr),
			err: E(
				WithCode(NotUnique),
				WithMsg("this thing must be unique"),
				WithOp("alice.Bob"),
				WithWrap(stdErr),
			),
			want: true,
		},
		{
			name:     "no match on Wrapped only stderror",
			template: T(stderrors.New("no match")),
			err: E(
				WithCode(RecordNotFound),
				WithMsg("this thing is missing"),
				WithOp("alice.Bob"),
				WithWrap(stdErr),
			),
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			got := Match(tt.template, tt.err)
			assert.Equal(tt.want, got)
		})
	}
}
