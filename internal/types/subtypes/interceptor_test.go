// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package subtypes

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/gen/testing/attribute"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/structpb"
)

func init() {
	globals.RegisterPrefixToResourceInfo("trsr", resource.Unknown, "test", globals.Subtype("sub_resource"))
	globals.RegisterPrefixToResourceInfo("trrp", resource.Unknown, "test", globals.Subtype("resource_plugin"))
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
							attrs, _ := structpb.NewStruct(map[string]any{
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
							attrs, _ := structpb.NewStruct(map[string]any{
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
							attrs, _ := structpb.NewStruct(map[string]any{
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
							attrs, _ := structpb.NewStruct(map[string]any{
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
							attrs, _ := structpb.NewStruct(map[string]any{
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
							attrs, _ := structpb.NewStruct(map[string]any{
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
							attrs, _ := structpb.NewStruct(map[string]any{
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
							attrs, _ := structpb.NewStruct(map[string]any{
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
							attrs, _ := structpb.NewStruct(map[string]any{
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
							attrs, _ := structpb.NewStruct(map[string]any{
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
						attrs, _ := structpb.NewStruct(map[string]any{
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
						attrs, _ := structpb.NewStruct(map[string]any{
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
						attrs, _ := structpb.NewStruct(map[string]any{
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
						attrs, _ := structpb.NewStruct(map[string]any{
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
						attrs, _ := structpb.NewStruct(map[string]any{
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
			err := transformRequest(context.Background(), tc.req)
			require.NoError(t, err)
			assert.Empty(t, cmp.Diff(tc.req, tc.expected, protocmp.Transform()))
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
								attrs, _ := structpb.NewStruct(map[string]any{
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
								attrs, _ := structpb.NewStruct(map[string]any{
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
								attrs, _ := structpb.NewStruct(map[string]any{
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
							attrs, _ := structpb.NewStruct(map[string]any{
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
							attrs, _ := structpb.NewStruct(map[string]any{
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
							attrs, _ := structpb.NewStruct(map[string]any{
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
							attrs, _ := structpb.NewStruct(map[string]any{
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
							attrs, _ := structpb.NewStruct(map[string]any{
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
						attrs, _ := structpb.NewStruct(map[string]any{
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
						attrs, _ := structpb.NewStruct(map[string]any{
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
						attrs, _ := structpb.NewStruct(map[string]any{
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
						attrs, _ := structpb.NewStruct(map[string]any{
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
			err := transformResponse(context.Background(), tc.resp)
			require.NoError(t, err)
			assert.Empty(t, cmp.Diff(tc.resp, tc.expected, protocmp.Transform()))
		})
	}
}

func TestCustomTransformRequest(t *testing.T) {
	require.NoError(t, RegisterRequestTransformationFunc(
		&attribute.TestCustomTransformation{},
		func(_ context.Context, m proto.Message) error {
			msg, ok := m.(*attribute.TestCustomTransformation)
			require.True(t, ok, "wrong message passed to request transformation callback")
			if msg.SomeRandomId == "some_random_id" && msg.SecondaryId == "secondary_id" {
				newAttrs := &attribute.TestSubResourceAttributes{}
				err := handlers.StructToProto(msg.GetAttributes(), newAttrs)
				require.NoError(t, err)
				msg.Attrs = &attribute.TestCustomTransformation_SubResourceAttributes{
					SubResourceAttributes: newAttrs,
				}
			}
			return nil
		},
	))
	request := &attribute.TestCustomTransformation{
		SomeRandomId: "some_random_id",
		SecondaryId:  "secondary_id",
		Attrs: &attribute.TestCustomTransformation_Attributes{
			Attributes: func() *structpb.Struct {
				attrs, _ := structpb.NewStruct(map[string]any{
					"name": "test",
				})
				return attrs
			}(),
		},
	}
	expected := &attribute.TestCustomTransformation{
		SomeRandomId: "some_random_id",
		SecondaryId:  "secondary_id",
		Attrs: &attribute.TestCustomTransformation_SubResourceAttributes{
			SubResourceAttributes: &attribute.TestSubResourceAttributes{
				Name: "test",
			},
		},
	}

	err := transformRequest(context.Background(), request)
	require.NoError(t, err)
	assert.Empty(t, cmp.Diff(request, expected, protocmp.Transform()))
}

func TestCustomTransformResponse(t *testing.T) {
	require.NoError(t, RegisterResponseTransformationFunc(
		&attribute.TestCustomTransformation{},
		func(_ context.Context, m proto.Message) error {
			msg, ok := m.(*attribute.TestCustomTransformation)
			require.True(t, ok, "wrong message passed to response transformation callback")
			if msg.SomeRandomId == "some_random_id" && msg.SecondaryId == "secondary_id" {
				newAttrs, err := handlers.ProtoToStruct(context.Background(), msg.GetSubResourceAttributes())
				require.NoError(t, err)
				msg.Attrs = &attribute.TestCustomTransformation_Attributes{
					Attributes: newAttrs,
				}
			}
			return nil
		},
	))
	response := &attribute.TestCustomTransformation{
		SomeRandomId: "some_random_id",
		SecondaryId:  "secondary_id",
		Attrs: &attribute.TestCustomTransformation_SubResourceAttributes{
			SubResourceAttributes: &attribute.TestSubResourceAttributes{
				Name: "test",
			},
		},
	}
	expected := &attribute.TestCustomTransformation{
		SomeRandomId: "some_random_id",
		SecondaryId:  "secondary_id",
		Attrs: &attribute.TestCustomTransformation_Attributes{
			Attributes: func() *structpb.Struct {
				attrs, _ := structpb.NewStruct(map[string]any{
					"name": "test",
				})
				return attrs
			}(),
		},
	}

	err := transformResponse(context.Background(), response)
	require.NoError(t, err)
	assert.Empty(t, cmp.Diff(response, expected, protocmp.Transform()))
}
