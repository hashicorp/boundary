package subtypes

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/internal/gen/testing/attribute"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/structpb"
)

func init() {
	Register("test", Subtype("sub_resource"), "trsr")
	Register("test", Subtype("resource_plugin"), "trrp")
}

func TestTransformRequestAttributes(t *testing.T) {
	cases := []struct {
		name     string
		req      proto.Message
		expected proto.Message
	}{
		{
			"TestCreateResource/SubResourceRequest",
			&attribute.TestCreateResourceRequest{
				Item: &attribute.TestResource{
					Type: "sub_resource",
					Attrs: &attribute.TestResource_Attributes{
						Attributes: func() *structpb.Struct {
							attrs, _ := structpb.NewStruct(map[string]interface{}{
								"name": "test",
							})
							return attrs
						}(),
					},
				},
			},
			&attribute.TestCreateResourceRequest{
				Item: &attribute.TestResource{
					Type: "sub_resource",
					Attrs: &attribute.TestResource_SubResourceAttributes{
						SubResourceAttributes: &attribute.TestSubResourceAttributes{
							Name: "test",
						},
					},
				},
			},
		},
		{
			"TestCreateResource/DefaultResourceRequest",
			&attribute.TestCreateResourceRequest{
				Item: &attribute.TestResource{
					Type: "default",
					Attrs: &attribute.TestResource_Attributes{
						Attributes: func() *structpb.Struct {
							attrs, _ := structpb.NewStruct(map[string]interface{}{
								"name": "test",
							})
							return attrs
						}(),
					},
				},
			},
			&attribute.TestCreateResourceRequest{
				Item: &attribute.TestResource{
					Type: "default",
					Attrs: &attribute.TestResource_Attributes{
						Attributes: func() *structpb.Struct {
							attrs, _ := structpb.NewStruct(map[string]interface{}{
								"name": "test",
							})
							return attrs
						}(),
					},
				},
			},
		},
		{
			"TestCreateResource/UnknownResourceRequest",
			&attribute.TestCreateResourceRequest{
				Item: &attribute.TestResource{
					Type: "unknown",
					Attrs: &attribute.TestResource_Attributes{
						Attributes: func() *structpb.Struct {
							attrs, _ := structpb.NewStruct(map[string]interface{}{
								"name": "test",
							})
							return attrs
						}(),
					},
				},
			},
			&attribute.TestCreateResourceRequest{
				Item: &attribute.TestResource{
					Type: "unknown",
					Attrs: &attribute.TestResource_Attributes{
						Attributes: func() *structpb.Struct {
							attrs, _ := structpb.NewStruct(map[string]interface{}{
								"name": "test",
							})
							return attrs
						}(),
					},
				},
			},
		},
		{
			"TestUpdateResource/SubResourceRequest",
			&attribute.TestUpdateResourceRequest{
				Id: "trsr_one",
				Item: &attribute.TestResource{
					Attrs: &attribute.TestResource_Attributes{
						Attributes: func() *structpb.Struct {
							attrs, _ := structpb.NewStruct(map[string]interface{}{
								"name": "test",
							})
							return attrs
						}(),
					},
				},
			},
			&attribute.TestUpdateResourceRequest{
				Id: "trsr_one",
				Item: &attribute.TestResource{
					Attrs: &attribute.TestResource_SubResourceAttributes{
						SubResourceAttributes: &attribute.TestSubResourceAttributes{
							Name: "test",
						},
					},
				},
			},
		},
		{
			"TestUpdateResource/PluginResourceRequest",
			&attribute.TestUpdateResourceRequest{
				Id: "trdp_one",
				Item: &attribute.TestResource{
					Attrs: &attribute.TestResource_Attributes{
						Attributes: func() *structpb.Struct {
							attrs, _ := structpb.NewStruct(map[string]interface{}{
								"name": "test",
							})
							return attrs
						}(),
					},
				},
			},
			&attribute.TestUpdateResourceRequest{
				Id: "trdp_one",
				Item: &attribute.TestResource{
					Attrs: &attribute.TestResource_Attributes{
						Attributes: func() *structpb.Struct {
							attrs, _ := structpb.NewStruct(map[string]interface{}{
								"name": "test",
							})
							return attrs
						}(),
					},
				},
			},
		},
		{
			"TestUpdateResource/UnknownResourceRequest",
			&attribute.TestUpdateResourceRequest{
				Id: "unknown",
				Item: &attribute.TestResource{
					Attrs: &attribute.TestResource_Attributes{
						Attributes: func() *structpb.Struct {
							attrs, _ := structpb.NewStruct(map[string]interface{}{
								"name": "test",
							})
							return attrs
						}(),
					},
				},
			},
			&attribute.TestUpdateResourceRequest{
				Id: "unknown",
				Item: &attribute.TestResource{
					Attrs: &attribute.TestResource_Attributes{
						Attributes: func() *structpb.Struct {
							attrs, _ := structpb.NewStruct(map[string]interface{}{
								"name": "test",
							})
							return attrs
						}(),
					},
				},
			},
		},
		{
			"TestRequestNoItem",
			&attribute.TestRequestNoItem{
				Name: "test",
			},
			&attribute.TestRequestNoItem{
				Name: "test",
			},
		},
		{
			"TestRequestItemNotMessage",
			&attribute.TestRequestItemNotMessage{
				Item: "test",
			},
			&attribute.TestRequestItemNotMessage{
				Item: "test",
			},
		},
		{
			"TestRequestItemNoType",
			&attribute.TestRequestItemNoType{
				Item: &attribute.TestItemNoType{
					Id: "test",
				},
			},
			&attribute.TestRequestItemNoType{
				Item: &attribute.TestItemNoType{
					Id: "test",
				},
			},
		},
		{
			"TestNoItemAttributes/SubResourceRequest",
			&attribute.TestNoItemAttributes{
				Id: "trsr_one",
				Attrs: &attribute.TestNoItemAttributes_Attributes{
					Attributes: func() *structpb.Struct {
						attrs, _ := structpb.NewStruct(map[string]interface{}{
							"name": "test",
						})
						return attrs
					}(),
				},
			},
			&attribute.TestNoItemAttributes{
				Id: "trsr_one",
				Attrs: &attribute.TestNoItemAttributes_SubResourceAttributes{
					SubResourceAttributes: &attribute.TestSubResourceAttributes{
						Name: "test",
					},
				},
			},
		},
		{
			"TestCreateNoOneOfRequest",
			&attribute.TestCreateNoOneOfRequest{
				Item: &attribute.TestNoOneOf{
					Type: "sub_resource",
					Attributes: func() *structpb.Struct {
						attrs, _ := structpb.NewStruct(map[string]interface{}{
							"name": "test",
						})
						return attrs
					}(),
				},
			},
			&attribute.TestCreateNoOneOfRequest{
				Item: &attribute.TestNoOneOf{
					Type: "sub_resource",
					Attributes: func() *structpb.Struct {
						attrs, _ := structpb.NewStruct(map[string]interface{}{
							"name": "test",
						})
						return attrs
					}(),
				},
			},
		},
		{
			"TestUpdateNoOneOfRequest",
			&attribute.TestUpdateNoOneOfRequest{
				Id: "trsr_one",
				Item: &attribute.TestNoOneOf{
					Attributes: func() *structpb.Struct {
						attrs, _ := structpb.NewStruct(map[string]interface{}{
							"name": "test",
						})
						return attrs
					}(),
				},
			},
			&attribute.TestUpdateNoOneOfRequest{
				Id: "trsr_one",
				Item: &attribute.TestNoOneOf{
					Attributes: func() *structpb.Struct {
						attrs, _ := structpb.NewStruct(map[string]interface{}{
							"name": "test",
						})
						return attrs
					}(),
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := transformRequestAttributes(tc.req)
			require.NoError(t, err)
			assert.Empty(t, cmp.Diff(got, tc.expected, protocmp.Transform()))
		})
	}
}

func TestTransformResponseAttributes(t *testing.T) {
	cases := []struct {
		name     string
		resp     proto.Message
		expected proto.Message
	}{
		{
			"TestListResourceResponse",
			&attribute.TestListResourceResponse{
				Items: []*attribute.TestResource{
					{
						Type: "sub_resource",
						Attrs: &attribute.TestResource_SubResourceAttributes{
							SubResourceAttributes: &attribute.TestSubResourceAttributes{
								Name: "test",
							},
						},
					},
					{
						Type: "default",
						Attrs: &attribute.TestResource_Attributes{
							Attributes: func() *structpb.Struct {
								attrs, _ := structpb.NewStruct(map[string]interface{}{
									"name": "test",
								})
								return attrs
							}(),
						},
					},
				},
			},
			&attribute.TestListResourceResponse{
				Items: []*attribute.TestResource{
					{
						Type: "sub_resource",
						Attrs: &attribute.TestResource_Attributes{
							Attributes: func() *structpb.Struct {
								attrs, _ := structpb.NewStruct(map[string]interface{}{
									"name": "test",
								})
								return attrs
							}(),
						},
					},
					{
						Type: "default",
						Attrs: &attribute.TestResource_Attributes{
							Attributes: func() *structpb.Struct {
								attrs, _ := structpb.NewStruct(map[string]interface{}{
									"name": "test",
								})
								return attrs
							}(),
						},
					},
				},
			},
		},
		{
			"TestGetResourceResponse/SubResourceAttributes",
			&attribute.TestGetResourceResponse{
				Item: &attribute.TestResource{
					Id:   "trsr_one",
					Type: "sub_resource",
					Attrs: &attribute.TestResource_SubResourceAttributes{
						SubResourceAttributes: &attribute.TestSubResourceAttributes{
							Name: "test",
						},
					},
				},
			},
			&attribute.TestGetResourceResponse{
				Item: &attribute.TestResource{
					Id:   "trsr_one",
					Type: "sub_resource",
					Attrs: &attribute.TestResource_Attributes{
						Attributes: func() *structpb.Struct {
							attrs, _ := structpb.NewStruct(map[string]interface{}{
								"name": "test",
							})
							return attrs
						}(),
					},
				},
			},
		},
		{
			"TestGetResourceResponse/PluginAttributes",
			&attribute.TestGetResourceResponse{
				Item: &attribute.TestResource{
					Id:   "trrp_one",
					Type: "plugin",
					Attrs: &attribute.TestResource_Attributes{
						Attributes: func() *structpb.Struct {
							attrs, _ := structpb.NewStruct(map[string]interface{}{
								"name": "test",
							})
							return attrs
						}(),
					},
				},
			},
			&attribute.TestGetResourceResponse{
				Item: &attribute.TestResource{
					Id:   "trrp_one",
					Type: "plugin",
					Attrs: &attribute.TestResource_Attributes{
						Attributes: func() *structpb.Struct {
							attrs, _ := structpb.NewStruct(map[string]interface{}{
								"name": "test",
							})
							return attrs
						}(),
					},
				},
			},
		},
		{
			"TestCreateResourceResponse",
			&attribute.TestCreateResourceResponse{
				Item: &attribute.TestResource{
					Id:   "trsr_one",
					Type: "sub_resource",
					Attrs: &attribute.TestResource_SubResourceAttributes{
						SubResourceAttributes: &attribute.TestSubResourceAttributes{
							Name: "test",
						},
					},
				},
			},
			&attribute.TestCreateResourceResponse{
				Item: &attribute.TestResource{
					Id:   "trsr_one",
					Type: "sub_resource",
					Attrs: &attribute.TestResource_Attributes{
						Attributes: func() *structpb.Struct {
							attrs, _ := structpb.NewStruct(map[string]interface{}{
								"name": "test",
							})
							return attrs
						}(),
					},
				},
			},
		},
		{
			"TestUpdateResourceResponse",
			&attribute.TestUpdateResourceResponse{
				Item: &attribute.TestResource{
					Id:   "trsr_one",
					Type: "sub_resource",
					Attrs: &attribute.TestResource_SubResourceAttributes{
						SubResourceAttributes: &attribute.TestSubResourceAttributes{
							Name: "test",
						},
					},
				},
			},
			&attribute.TestUpdateResourceResponse{
				Item: &attribute.TestResource{
					Id:   "trsr_one",
					Type: "sub_resource",
					Attrs: &attribute.TestResource_Attributes{
						Attributes: func() *structpb.Struct {
							attrs, _ := structpb.NewStruct(map[string]interface{}{
								"name": "test",
							})
							return attrs
						}(),
					},
				},
			},
		},
		{
			"TestResponseNoItem",
			&attribute.TestResponseNoItem{
				Name: "test",
			},
			&attribute.TestResponseNoItem{
				Name: "test",
			},
		},
		{
			"TestResponseItemNotMessage",
			&attribute.TestResponseItemNotMessage{
				Item: "test",
			},
			&attribute.TestResponseItemNotMessage{
				Item: "test",
			},
		},
		{
			"TestResponseItemNoType",
			&attribute.TestResponseItemNoType{
				Item: &attribute.TestItemNoType{
					Id: "test",
				},
			},
			&attribute.TestResponseItemNoType{
				Item: &attribute.TestItemNoType{
					Id: "test",
				},
			},
		},
		{
			"TestCreateNoOneOfResponse",
			&attribute.TestCreateNoOneOfResponse{
				Item: &attribute.TestNoOneOf{
					Id:   "trsr_one",
					Type: "sub_resource",
					Attributes: func() *structpb.Struct {
						attrs, _ := structpb.NewStruct(map[string]interface{}{
							"name": "test",
						})
						return attrs
					}(),
				},
			},
			&attribute.TestCreateNoOneOfResponse{
				Item: &attribute.TestNoOneOf{
					Id:   "trsr_one",
					Type: "sub_resource",
					Attributes: func() *structpb.Struct {
						attrs, _ := structpb.NewStruct(map[string]interface{}{
							"name": "test",
						})
						return attrs
					}(),
				},
			},
		},
		{
			"TestUpdateNoOneOfResponse",
			&attribute.TestUpdateNoOneOfResponse{
				Item: &attribute.TestNoOneOf{
					Id:   "trsr_one",
					Type: "sub_resource",
					Attributes: func() *structpb.Struct {
						attrs, _ := structpb.NewStruct(map[string]interface{}{
							"name": "test",
						})
						return attrs
					}(),
				},
			},
			&attribute.TestUpdateNoOneOfResponse{
				Item: &attribute.TestNoOneOf{
					Id:   "trsr_one",
					Type: "sub_resource",
					Attributes: func() *structpb.Struct {
						attrs, _ := structpb.NewStruct(map[string]interface{}{
							"name": "test",
						})
						return attrs
					}(),
				},
			},
		},
		{
			"TestCreateResourceOneofUnset",
			&attribute.TestCreateResourceResponse{
				Item: &attribute.TestResource{
					Id:   "trsr_one",
					Type: "sub_resource",
				},
			},
			&attribute.TestCreateResourceResponse{
				Item: &attribute.TestResource{
					Id:   "trsr_one",
					Type: "sub_resource",
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := transformResponseAttributes(tc.resp)
			require.NoError(t, err)
			assert.Empty(t, cmp.Diff(got, tc.expected, protocmp.Transform()))
		})
	}
}
