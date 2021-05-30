package event

import (
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/gen/controller/api/resources/groups"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// Test_GetOpts provides unit tests for GetOpts and all the options
func Test_GetOpts(t *testing.T) {
	t.Parallel()
	t.Run("WithId", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithId("test"))
		testOpts := getDefaultOptions()
		testOpts.withId = "test"
		assert.Equal(opts, testOpts)
	})
	t.Run("WithDetails", func(t *testing.T) {
		assert := assert.New(t)
		d := map[string]interface{}{
			"name": "alice",
		}
		opts := getOpts(WithDetails(d))
		testOpts := getDefaultOptions()
		testOpts.withDetails = d
		assert.Equal(opts, testOpts)
	})
	t.Run("WithHeader", func(t *testing.T) {
		assert := assert.New(t)
		h := map[string]interface{}{
			"name": "alice",
		}
		opts := getOpts(WithHeader(h))
		testOpts := getDefaultOptions()
		testOpts.withHeader = h
		assert.Equal(opts, testOpts)
	})
	t.Run("WithFlush", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithFlush())
		testOpts := getDefaultOptions()
		testOpts.withFlush = true
		assert.Equal(opts, testOpts)
	})
	t.Run("WithRequestInfo", func(t *testing.T) {
		assert := assert.New(t)
		info := &RequestInfo{
			Id:       "test-id",
			Method:   "POST",
			Path:     "/test/path",
			PublicId: "public-id",
		}
		opts := getOpts(WithRequestInfo(info))
		testOpts := getDefaultOptions()
		testOpts.withRequestInfo = info
		assert.Equal(opts, testOpts)
	})
	t.Run("WithNow", func(t *testing.T) {
		assert := assert.New(t)
		now := time.Now()
		opts := getOpts(WithNow(now))
		testOpts := getDefaultOptions()
		testOpts.withNow = now
		assert.Equal(opts, testOpts)
	})
	t.Run("WithRequest", func(t *testing.T) {
		assert := assert.New(t)
		r := &Request{
			Operation: "op",
			Endpoint:  "/group/<id>",
			Details: &pbs.GetGroupRequest{
				Id: "group-id",
			},
		}
		opts := getOpts(WithRequest(r))
		testOpts := getDefaultOptions()
		testOpts.withRequest = r
		assert.Equal(opts, testOpts)
	})
	t.Run("WithResponse", func(t *testing.T) {
		assert := assert.New(t)
		r := &Response{
			StatusCode: 200,
			Details: &pbs.GetGroupResponse{
				Item: &groups.Group{
					Id:      "group-id",
					ScopeId: "org-id",
					Name: &wrapperspb.StringValue{
						Value: "group-name",
					},
				},
			},
		}
		opts := getOpts(WithResponse(r))
		testOpts := getDefaultOptions()
		testOpts.withResponse = r
		assert.Equal(opts, testOpts)
	})
	t.Run("WithAuth", func(t *testing.T) {
		assert := assert.New(t)
		auth := Auth{
			UserEmail: "alice@eve.com",
			UserName:  "alice eve smith",
		}
		opts := getOpts(WithAuth(&auth))
		testOpts := getDefaultOptions()
		testOpts.withAuth = &auth
		assert.Equal(opts, testOpts)
	})
}
