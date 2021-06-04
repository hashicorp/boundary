package event

import (
	"testing"

	"github.com/hashicorp/boundary/internal/gen/controller/api/resources/groups"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// TestRequestInfo provides a test RequestInfo
func TestRequestInfo(t *testing.T) *RequestInfo {
	t.Helper()
	return &RequestInfo{
		Id:       "test-request-info",
		Method:   "POST",
		Path:     "/test/request/info",
		PublicId: "public-id",
	}
}

func testAuth(t *testing.T) *Auth {
	t.Helper()
	return &Auth{
		UserEmail: "test-auth@example.com",
		UserName:  "test-auth-user-name",
	}
}

func testRequest(t *testing.T) *Request {
	t.Helper()
	return &Request{
		Operation: "op",
		Endpoint:  "/group/<id>",
		Details: &pbs.GetGroupRequest{
			Id: "group-id",
		},
	}
}

func testResponse(t *testing.T) *Response {
	t.Helper()
	return &Response{
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
}
