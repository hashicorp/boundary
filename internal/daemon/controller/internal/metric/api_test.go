// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package metric

import (
	"net/http"
	"testing"

	"github.com/hashicorp/boundary/internal/gen/testing/protooptions"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildRegexFromPath(t *testing.T) {
	cases := []struct {
		path  string
		match []string
		dont  []string
	}{
		{
			path: "/v1/pathsomething/{id}:test-thing",
			match: []string{
				"/v1/pathsomething/a4s_aKsdFh723018djsa:test-thing",
				"/v1/pathsomething/h_1234567890:test-thing",
				"/v1/pathsomething/{id}:test-thing",
				"/v1/pathsomething/{any_old_id}:test-thing",
				"/v1/pathsomething/not-an-id:test-thing",
			},
			dont: []string{
				"/v1/pathsomething/a4s_aKsdFh723018djsa:other-thing",
				"/v1/pathsomething:test-thing",
				"/v1/pathsomething/:test-thing:test-thing",
				"/v1/pathsomething/:other-thing",
			},
		},
		{
			path: "/v1/pathsomething/{auth_method_id}:authenticate",
			match: []string{
				"/v1/pathsomething/a4s_aKsdFh723018djsa:authenticate",
				"/v1/pathsomething/am_1234567890:authenticate",
				"/v1/pathsomething/{id}:authenticate",
				"/v1/pathsomething/{auth_method}:authenticate",
				"/v1/pathsomething/am_1234567890/:authenticate",
			},
			dont: []string{
				"/v1/pathsomething:authenticate",
				"/v1/pathsomething:authenticate:authenticate",
				"/v1/pathsomething/:authenticate:authenticate",
				"/v1/pathsomething/?whatabout=:authenticate",
			},
		},
		{
			path: "/v1/pathsomething/{non_id_tag}:test",
			match: []string{
				"/v1/pathsomething/{non_id_tag}:test",
			},
			dont: []string{
				"/v1/pathsomething/h_1234567890:test",
				"/v1/pathsomething/.*:test",
			},
		},
		{
			path: "/v1/pathsomething/a?",
			match: []string{
				"/v1/pathsomething/a?",
			},
			dont: []string{
				"/v1/pathsomething/",
				"/v1/pathsomething/a",
				"/v1/pathsomething/aa",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			r := buildRegexFromPath(tc.path)
			for _, m := range tc.match {
				assert.True(t, r.Match([]byte(m)), "Couldn't match %q", m)
			}
			for _, d := range tc.dont {
				assert.False(t, r.Match([]byte(d)), "Matched %q", d)
			}
		})
	}
}

func TestPathLabel(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{
			in:   "/v1/accounts",
			want: "/v1/accounts",
		},
		{
			in:   "v1/accounts",
			want: "/v1/accounts",
		},
		{
			in:   "/v1/hosts",
			want: "/v1/hosts",
		},
		{
			in:   "/v2/accounts",
			want: "invalid",
		},
		{
			in:   "/v1/accounts/a_1234567890",
			want: "/v1/accounts/{id}",
		},
		{
			in:   "/v1/accounts/mistake",
			want: "/v1/accounts/{id}",
		},
		{
			in:   "/v1/accounts/mistyped_id",
			want: "/v1/accounts/{id}",
		},
		{
			in:   "v1/accounts/a_1234567890",
			want: "/v1/accounts/{id}",
		},
		{
			in:   "/v1/accounts/a_1234567890:set-password",
			want: "/v1/accounts/{id}:set-password",
		},
		{
			in:   "v1/accounts/a_1234567890:set-password",
			want: "/v1/accounts/{id}:set-password",
		},
		{
			// using target id
			in:   "/v1/targets/tssh_12345789:authorize-session",
			want: "/v1/targets/{id=**}:authorize-session",
		},
		{
			// using target name
			in:   "/v1/targets/foo-target:authorize-session",
			want: "/v1/targets/{id=**}:authorize-session",
		},
		{
			// using target name with a space
			in:   "/v1/targets/foo target:authorize-session",
			want: "/v1/targets/{id=**}:authorize-session",
		},
		{
			// using target name with a slash
			in:   "/v1/targets/foo/target:authorize-session",
			want: "/v1/targets/{id=**}:authorize-session",
		},
		{
			// using alias
			in:   "/v1/targets/foo.test:authorize-session",
			want: "/v1/targets/{id=**}:authorize-session",
		},
		{
			// mistype the custom action
			in:   "/v1/accounts/a_1234567890:set-passwords",
			want: "invalid",
		},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			assert.Equal(t, tc.want, pathLabel(tc.in))
		})
	}
}

func TestServicePathsAndMethods(t *testing.T) {
	paths := make(map[string][]string)
	require.NoError(t, gatherServicePathsAndMethods(protooptions.File_testing_options_v1_service_proto, paths))
	assert.Equal(t, map[string][]string{
		"/v1/test/{id}": {http.MethodGet},
		"/v2/test":      {http.MethodGet},
	}, paths)
}
