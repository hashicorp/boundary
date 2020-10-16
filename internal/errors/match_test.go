package errors

import (
	stderrors "errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestT(t *testing.T) {

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
