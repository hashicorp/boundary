// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPathCapabilities_has(t *testing.T) {
	type hasCheck struct {
		p string
		t []capabilities
		f []capabilities
	}

	tests := []struct {
		name   string
		given  map[string][]string
		checks []hasCheck
	}{
		{
			name: "empty",
			checks: []hasCheck{
				{
					p: "one",
					f: []capabilities{
						createCapability, readCapability, updateCapability,
						deleteCapability, listCapability, sudoCapability,
						rootCapability,
					},
				},
			},
		},
		{
			name: "one-path-no-capabilities",
			given: map[string][]string{
				"one": {""},
			},
			checks: []hasCheck{
				{
					p: "one",
					f: []capabilities{
						createCapability, readCapability, updateCapability,
						deleteCapability, listCapability, sudoCapability,
						rootCapability,
					},
				},
			},
		},
		{
			name: "one-path-deny",
			given: map[string][]string{
				"one": {"deny"},
			},
			checks: []hasCheck{
				{
					p: "one",
					f: []capabilities{
						createCapability, readCapability, updateCapability,
						deleteCapability, listCapability, sudoCapability,
						rootCapability,
					},
				},
			},
		},
		{
			name: "one-path-deny-and-others",
			given: map[string][]string{
				"one": {"deny", "create", "update"},
			},
			checks: []hasCheck{
				{
					p: "one",
					f: []capabilities{
						createCapability, readCapability, updateCapability,
						deleteCapability, listCapability, sudoCapability,
						rootCapability,
					},
				},
			},
		},
		{
			name: "one-path-one-capability",
			given: map[string][]string{
				"one": {"create"},
			},
			checks: []hasCheck{
				{
					p: "one",
					t: []capabilities{
						createCapability,
					},
					f: []capabilities{
						readCapability, updateCapability,
						deleteCapability, listCapability, sudoCapability,
						rootCapability,
					},
				},
			},
		},
		{
			name: "one-path-multiple-capabilities",
			given: map[string][]string{
				"one": {"create", "update"},
			},
			checks: []hasCheck{
				{
					p: "one",
					t: []capabilities{
						createCapability, updateCapability,
					},
					f: []capabilities{
						readCapability,
						deleteCapability, listCapability, sudoCapability,
						rootCapability,
					},
				},
			},
		},
		{
			name: "one-path-all-capabilities",
			given: map[string][]string{
				"one": {"create", "read", "update", "delete", "list", "sudo", "root"},
			},
			checks: []hasCheck{
				{
					p: "one",
					t: []capabilities{
						createCapability, readCapability, updateCapability,
						deleteCapability, listCapability, sudoCapability,
						rootCapability,
					},
				},
			},
		},
		{
			name: "one-path-all-capabilities-plus-unknown",
			given: map[string][]string{
				"one": {"create", "read", "update", "delete", "list", "sudo", "root", "stuff"},
			},
			checks: []hasCheck{
				{
					p: "one",
					t: []capabilities{
						createCapability, readCapability, updateCapability,
						deleteCapability, listCapability, sudoCapability,
						rootCapability,
					},
				},
			},
		},
		{
			name: "one-path-all-capabilities-ignore-required-deny",
			given: map[string][]string{
				"one": {"create", "read", "update", "delete", "list", "sudo", "root"},
			},
			checks: []hasCheck{
				{
					p: "one",
					t: []capabilities{
						denyCapability,
						createCapability, readCapability, updateCapability,
						deleteCapability, listCapability, sudoCapability,
						rootCapability,
					},
				},
			},
		},
		{
			name: "two-paths-multiple-capabilities",
			given: map[string][]string{
				"one": {"create", "update"},
				"two": {"read", "update"},
			},
			checks: []hasCheck{
				{
					p: "one",
					t: []capabilities{
						createCapability, updateCapability,
					},
					f: []capabilities{
						readCapability,
						deleteCapability, listCapability, sudoCapability,
						rootCapability,
					},
				},
				{
					p: "two",
					t: []capabilities{
						readCapability, updateCapability,
					},
					f: []capabilities{
						createCapability,
						deleteCapability, listCapability, sudoCapability,
						rootCapability,
					},
				},
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			got := newPathCapabilities(tt.given)
			for _, check := range tt.checks {
				for _, cap := range check.t {
					switch {
					case cap.hasDeny():
						assert.False(got.has(check.p, cap))
					default:
						assert.True(got.has(check.p, cap))
					}
				}
				if len(check.t) > 0 {
					assert.True(got.has(check.p, check.t...))
				}
				for _, cap := range check.f {
					assert.False(got.has(check.p, cap))
				}
			}
		})
	}
}

func TestPathCapabilities_get(t *testing.T) {
	type getCheck struct {
		p      string
		want   capabilities
		wantOk bool
	}

	tests := []struct {
		name   string
		given  map[string][]string
		checks []getCheck
	}{
		{
			name: "empty",
			checks: []getCheck{
				{
					p: "one",
				},
			},
		},
		{
			name: "one-path-no-capabilities",
			given: map[string][]string{
				"one": {""},
			},
			checks: []getCheck{
				{
					p:      "one",
					wantOk: true,
				},
			},
		},
		{
			name: "one-path-deny",
			given: map[string][]string{
				"one": {"deny"},
			},
			checks: []getCheck{
				{
					p:      "one",
					wantOk: true,
					want:   denyCapability,
				},
			},
		},
		{
			name: "one-path-deny-and-others",
			given: map[string][]string{
				"one": {"deny", "create", "update"},
			},
			checks: []getCheck{
				{
					p:      "one",
					wantOk: true,
					want:   denyCapability | createCapability | updateCapability,
				},
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			pc := newPathCapabilities(tt.given)
			for _, check := range tt.checks {
				got, gotOk := pc.get(check.p)
				assert.Equalf(check.want, got, "capabilities: want: %q got: %q", check.want, got)
				assert.Equal(check.wantOk, gotOk, "ok")
			}
		})
	}
}

func TestPathCapabilities_vaultPolicy(t *testing.T) {
	const (
		onePathOneCap string = `path "one" {
	capabilities = ["create"]
}
`

		twoPathsOneCap string = `path "one" {
	capabilities = ["create"]
}

path "two" {
	capabilities = ["create"]
}
`

		onePathTwoCaps string = `path "one" {
	capabilities = ["create", "list"]
}
`
	)

	tests := []struct {
		name  string
		given pathCapabilities
		want  string
	}{
		{
			name: "empty",
		},
		{
			name: "onePathNoCap",
			given: pathCapabilities{
				"one": noCapabilities,
			},
		},
		{
			name: "onePathOneCap",
			want: onePathOneCap,
			given: pathCapabilities{
				"one": createCapability,
			},
		},
		{
			name: "twoPathsOneAndNoCap",
			want: onePathOneCap,
			given: pathCapabilities{
				"one": createCapability,
				"two": noCapabilities,
			},
		},
		{
			name: "twoPathsOneCap",
			want: twoPathsOneCap,
			given: pathCapabilities{
				"one": createCapability,
				"two": createCapability,
			},
		},
		{
			name: "onePathTwoCaps",
			want: onePathTwoCaps,
			given: pathCapabilities{
				"one": createCapability | listCapability,
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got := tt.given.vaultPolicy()
			t.Log(got)
			assert.Equal(t, tt.want, got)
		})
	}
}

func assertDifferentMaps(t *testing.T, a, b, got pathCapabilities) {
	t.Helper()
	assert := assert.New(t)
	aptr, bptr, gotptr := reflect.ValueOf(a).Pointer(), reflect.ValueOf(b).Pointer(), reflect.ValueOf(got).Pointer()
	if a != nil {
		assert.NotEqual(aptr, gotptr, "a and got are the same map")
	}
	if b != nil {
		assert.NotEqual(bptr, gotptr, "b and got are the same map")
	}
	if a != nil && b != nil {
		assert.NotEqual(aptr, bptr, "a and b are the same map")
	}
}

func TestPathCapabilities_union(t *testing.T) {
	check := func(t *testing.T, x, y, z pathCapabilities) {
		got := x.union(y)
		assert.Equal(t, z, got)
		assertDifferentMaps(t, x, y, got)
	}
	tests := []struct {
		name    string
		x, y, z pathCapabilities
	}{
		{
			name: "x-y-empty",
		},
		{
			name: "x-empty",
			y:    pathCapabilities{"one": createCapability},
			z:    pathCapabilities{"one": createCapability},
		},
		{
			name: "y-empty",
			x:    pathCapabilities{"one": createCapability},
			z:    pathCapabilities{"one": createCapability},
		},
		{
			name: "identical",
			x:    pathCapabilities{"one": createCapability},
			y:    pathCapabilities{"one": createCapability},
			z:    pathCapabilities{"one": createCapability},
		},
		{
			name: "multiple-capabilities",
			x:    pathCapabilities{"one": createCapability},
			y:    pathCapabilities{"one": listCapability},
			z:    pathCapabilities{"one": createCapability | listCapability},
		},
		{
			name: "multiple-paths",
			x:    pathCapabilities{"one": createCapability},
			y:    pathCapabilities{"two": createCapability},
			z:    pathCapabilities{"one": createCapability, "two": createCapability},
		},
		{
			name: "multiple-paths-multiple-capabilities",
			x: pathCapabilities{
				"one":   createCapability | listCapability,
				"two":   createCapability | readCapability,
				"three": sudoCapability,
			},
			y: pathCapabilities{
				"one":  createCapability | updateCapability,
				"two":  createCapability | deleteCapability,
				"four": denyCapability,
			},
			z: pathCapabilities{
				"one":   createCapability | listCapability | updateCapability,
				"two":   createCapability | readCapability | deleteCapability,
				"three": sudoCapability,
				"four":  denyCapability,
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			// test the union method is commutative
			check(t, tt.x, tt.y, tt.z)
			check(t, tt.y, tt.x, tt.z)
		})
	}
}

func TestPathCapabilities_missing(t *testing.T) {
	tests := []struct {
		name                string
		have, require, want pathCapabilities
	}{
		{
			name: "empty-empty",
		},
		{
			name:    "empty-have",
			require: pathCapabilities{"one": createCapability},
			want:    pathCapabilities{"one": createCapability},
		},
		{
			name: "empty-required",
			have: pathCapabilities{"one": createCapability},
		},
		{
			name:    "have-and-require-equal",
			have:    pathCapabilities{"one": createCapability},
			require: pathCapabilities{"one": createCapability},
		},
		{
			name:    "one-path-missing-capability",
			have:    pathCapabilities{"one": createCapability},
			require: pathCapabilities{"one": readCapability},
			want:    pathCapabilities{"one": readCapability},
		},
		{
			name:    "one-path-missing-multiple-capabilities",
			have:    pathCapabilities{"one": createCapability},
			require: pathCapabilities{"one": createCapability | readCapability | updateCapability},
			want:    pathCapabilities{"one": readCapability | updateCapability},
		},
		{
			name:    "two-paths-one-missing-capabilities-one-not",
			have:    pathCapabilities{"one": createCapability, "two": createCapability},
			require: pathCapabilities{"one": readCapability, "two": createCapability},
			want:    pathCapabilities{"one": readCapability},
		},
		{
			name:    "two-paths-both-missing-capabilities",
			have:    pathCapabilities{"one": createCapability, "two": createCapability},
			require: pathCapabilities{"one": readCapability, "two": readCapability},
			want:    pathCapabilities{"one": readCapability, "two": readCapability},
		},
		{
			name:    "have-one-path-require-two-paths",
			have:    pathCapabilities{"one": createCapability},
			require: pathCapabilities{"one": readCapability, "two": readCapability},
			want:    pathCapabilities{"one": readCapability, "two": readCapability},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			got := tt.have.missing(tt.require)
			assertDifferentMaps(t, tt.have, tt.require, got)
			assert.Equalf(tt.want, got, "pathCapabilities: want: {%s} got: {%s}", tt.want, got)
		})
	}
}

func TestPathCapabilities_String(t *testing.T) {
	tests := []struct {
		name     string
		pc       pathCapabilities
		contains []string
	}{
		{
			name: "empty-empty",
		},
		{
			name:     "one-path",
			pc:       pathCapabilities{"one": createCapability},
			contains: []string{"one: create"},
		},
		{
			name:     "one-path-multiple-capabilities",
			pc:       pathCapabilities{"one": createCapability | readCapability | updateCapability},
			contains: []string{"one: create|read|update"},
		},
		{
			name:     "multiple-paths",
			pc:       pathCapabilities{"one": createCapability, "two": updateCapability},
			contains: []string{"one: create", "two: update"},
		},
		{
			name: "multiple-paths-multiple-capabilities",
			pc: pathCapabilities{
				"one":   createCapability,
				"two":   createCapability | readCapability | updateCapability,
				"three": readCapability | deleteCapability,
			},
			contains: []string{"one: create", "two: create|read|update", "three: read|delete"},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			got := tt.pc.String()
			for _, s := range tt.contains {
				assert.Containsf(got, s, "expected %q to contain %s", got, s)
			}
		})
	}
}

func TestCapabilities_missing(t *testing.T) {
	tests := []struct {
		have, require, want capabilities
	}{
		{
			have:    noCapabilities,
			require: noCapabilities,
			want:    noCapabilities,
		},
		{
			have:    createCapability,
			require: createCapability,
		},
		{
			have:    createCapability,
			require: createCapability | listCapability,
			want:    listCapability,
		},
		{
			have:    createCapability | readCapability,
			require: createCapability | listCapability,
			want:    listCapability,
		},
		{
			have:    createCapability | readCapability,
			require: deleteCapability | listCapability,
			want:    deleteCapability | listCapability,
		},
	}
	for _, tt := range tests {
		tt := tt
		name := fmt.Sprintf("{%s} - {%s} = {%s}", tt.require, tt.have, tt.want)
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)
			got := tt.have.missing(tt.require)
			assert.Equalf(tt.want, got, "capabilities: want: {%s} got: {%s}", tt.want, got)
		})
	}
}

func TestCapabilities_String(t *testing.T) {
	tests := []struct {
		name  string
		given capabilities
		want  string
	}{
		{"empty", noCapabilities, "[]"},
		{"one", createCapability, `["create"]`},
		{"two", createCapability | updateCapability, `["create", "update"]`},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got := tt.given.String()
			if got != tt.want {
				t.Errorf("(%s): want %s, got %s", tt.given, tt.want, got)
			}
		})
	}
}
