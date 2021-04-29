package logger

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/hashicorp/boundary/internal/servers/controller"
)

func Test_Event(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", t.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	sinkDir := filepath.Join(tmpDir, "file_sink")

	config := EventSink{
		Path:     sinkDir,
		FileName: "event.log",
	}

	c := controller.NewTestController(t, &controller.TestControllerOpts{
		DisableAuthorizationFailures: true,
	})
	defer c.Shutdown()
	url := fmt.Sprintf("%s/%s", c.ApiAddrs()[0], "v1/accounts")
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		t.Errorf("error making request, %w", err)
	}

	ctx := req.Context()
	test := []struct {
		name string
		ctx  context.Context
		req  *http.Request
	}{
		{
			name: "test",
			ctx:  ctx,
			req:  req,
		},
	}

	for _, v := range test {
		t.Run(v.name, func(t *testing.T) {
			ctx.Done()
			e, _ := NewEventer(config)
			payload := EventReq(req)
			err = e.WriteEvent("test", payload, ctx)
			if err != nil {
				t.Errorf("error in write, %w", err)
			}
			b, err := ioutil.ReadFile(sinkDir + "/event.log")
			if err != nil {
				t.Errorf("failed read, %w", err)
			}
			t.Logf("got: %v", b)
		})
	}
}
