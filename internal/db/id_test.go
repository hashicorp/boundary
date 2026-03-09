// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package db

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewPublicId(t *testing.T) {
	type args struct {
		prefix string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
		wantLen int
	}{
		{
			name: "valid",
			args: args{
				prefix: "id",
			},
			wantErr: false,
			wantLen: 10 + len("id_"),
		},
		{
			name: "bad-prefix",
			args: args{
				prefix: "",
			},
			wantErr: true,
			wantLen: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewPublicId(context.Background(), tt.args.prefix)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewPublicId() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && !strings.HasPrefix(got, tt.args.prefix+"_") {
				t.Errorf("NewPublicId() = %v, wanted it to start with %v", got, tt.args.prefix)
			}
			if len(got) != tt.wantLen {
				t.Errorf("NewPublicId() = %v, with len of %d and wanted len of %v", got, len(got), tt.wantLen)
			}
		})
	}
}

func TestNewPrivateId(t *testing.T) {
	type args struct {
		prefix string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
		wantLen int
	}{
		{
			name: "valid",
			args: args{
				prefix: "id",
			},
			wantErr: false,
			wantLen: 10 + len("id_"),
		},
		{
			name: "bad-prefix",
			args: args{
				prefix: "",
			},
			wantErr: true,
			wantLen: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := NewPrivateId(context.Background(), tt.args.prefix)
			if tt.wantErr {
				assert.Error(err)
				return
			}
			require.NoError(err)
			assert.True(strings.HasPrefix(got, tt.args.prefix+"_"))
			assert.Equal(tt.wantLen, len(got))
		})
	}
}

func TestPseudoRandomId(t *testing.T) {
	type args struct {
		prngValues []string
	}
	tests := []struct {
		name       string
		args       args
		sameAsPrev bool
	}{
		{
			name: "valid first",
			args: args{},
		},
		{
			name: "valid second",
			args: args{},
		},
		{
			name: "first prng",
			args: args{prngValues: []string{"foo", "bar"}},
		},
		{
			name:       "first prng verify",
			args:       args{prngValues: []string{"foo", "bar"}},
			sameAsPrev: true,
		},
		{
			name: "second prng",
			args: args{prngValues: []string{"bar", "foo"}},
		},
		{
			name:       "second prng verify",
			args:       args{prngValues: []string{"bar", "foo"}},
			sameAsPrev: true,
		},
	}
	var prevTestValue string
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := NewPublicId(context.Background(), "id", WithPrngValues(tt.args.prngValues))
			require.NoError(err)
			if tt.sameAsPrev {
				assert.Equal(prevTestValue, got)
			}
			prevTestValue = got
		})
	}
}
