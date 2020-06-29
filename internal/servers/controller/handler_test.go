package controller

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandleGrpcGateway(t *testing.T) {
	c := NewTestController(t, nil)
	defer c.Shutdown()

	cases := []struct {
		name string
		path string
		code int
	}{
		{
			"Non existent path",
			"v1/this-is-made-up",
			http.StatusNotFound,
		},
		{
			"Unimplemented path",
			"v1/orgs/1/projects/2/host-catalogs/3/host-sets/4",
			http.StatusMethodNotAllowed,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			url := fmt.Sprintf("%s/%s", c.ApiAddrs()[0], tc.path)
			resp, err := http.Get(url)
			if err != nil {
				t.Errorf("Got error: %v when non was expected.", err)
			}
			if got, want := resp.StatusCode, tc.code; got != want {
				t.Errorf("GET on %q got code %d, wanted %d", tc.path, got, want)
			}
		})
	}
}

func TestHandleDevPassthrough(t *testing.T) {
	// Create a temporary directory
	tempDir, err := ioutil.TempDir("", "watchtower-test-")
	require.NoError(t, err)
	defer func() {
		assert.NoError(t, os.RemoveAll(tempDir))
	}()

	nameContentsMap := map[string]string{
		"index.html":         `index`,
		"favicon.png":        `favicon`,
		"/assets/styles.css": `css`,
		"index.htm":          `badindex`,
	}

	for k, v := range nameContentsMap {
		dir := filepath.Dir(k)
		if dir != "/" {
			require.NoError(t, os.MkdirAll(filepath.Join(tempDir, dir), 0755))
		}
		require.NoError(t, ioutil.WriteFile(filepath.Join(tempDir, k), []byte(v), 0644))
	}

	c := NewTestController(t, &TestControllerOpts{DisableAutoStart: true})

	c.c.conf.RawConfig.PassthroughDirectory = tempDir
	require.NoError(t, c.c.Start())
	defer c.Shutdown()

	cases := []struct {
		name        string
		path        string
		contentsKey string
		code        int
		mimeType    string
	}{
		{
			"direct index",
			"index.html",
			"index.html",
			http.StatusOK,
			"text/html; charset=utf-8",
		},
		{
			"base slash",
			"",
			"index.html",
			http.StatusOK,
			"text/html; charset=utf-8",
		},
		{
			"no extension",
			"orgs",
			"index.html",
			http.StatusOK,
			"text/html; charset=utf-8",
		},
		{
			"favicon",
			"favicon.png",
			"favicon.png",
			http.StatusOK,
			"image/png",
		},
		{
			"bad index",
			"index.htm",
			"index.htm",
			http.StatusOK,
			"text/html; charset=utf-8",
		},
		{
			"bad path",
			"index.ht",
			"index.ht",
			http.StatusNotFound,
			"text/plain; charset=utf-8",
		},
		{
			"css",
			"assets/styles.css",
			"assets/styles.css",
			http.StatusOK,
			"text/css; charset=utf-8",
		},
		{
			"invalid extension",
			"foo.bāb",
			"index.html",
			http.StatusOK,
			"text/html; charset=utf-8",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert := assert.New(t)

			url := fmt.Sprintf("%s/%s", c.ApiAddrs()[0], tc.path)
			resp, err := http.Post(url, "", nil)
			assert.NoError(err)
			assert.Equal(http.StatusMethodNotAllowed, resp.StatusCode)

			resp, err = http.Get(url)
			assert.NoError(err)
			assert.Equal(tc.code, resp.StatusCode)
			assert.Equal(tc.mimeType, resp.Header.Get("content-type"))

			contents, ok := nameContentsMap[tc.contentsKey]
			if ok {
				reader := new(bytes.Buffer)
				_, err = reader.ReadFrom(resp.Body)
				assert.NoError(err)
				assert.Equal(contents, reader.String())
			}
		})
	}
}
