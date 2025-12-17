// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package subtypes_test

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/gen/testing/attribute"
	"github.com/hashicorp/boundary/internal/types/subtypes"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestAttributeTransformerInterceptor(t *testing.T) {
	cases := []struct {
		name             string
		req              any
		handlerResp      any
		expectHandlerReq any
		excpetResp       any
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
			"TestCreateResource/SubResourceRequest/OtherId",
			&attribute.TestCreateResourceRequest{
				Item: &attribute.TestResource{
					OtherId: "trsr_parent",
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
			&attribute.TestCreateResourceResponse{
				Item: &attribute.TestResource{
					Id:      "trsr_one",
					OtherId: "trsr_parent",
					Type:    "sub_resource",
					Attrs: &attribute.TestResource_SubResourceAttributes{
						SubResourceAttributes: &attribute.TestSubResourceAttributes{
							Name: "test",
						},
					},
				},
			},
			&attribute.TestCreateResourceRequest{
				Item: &attribute.TestResource{
					OtherId: "trsr_parent",
					Attrs: &attribute.TestResource_SubResourceAttributes{
						SubResourceAttributes: &attribute.TestSubResourceAttributes{
							Name: "test",
						},
					},
				},
			},
			&attribute.TestCreateResourceResponse{
				Item: &attribute.TestResource{
					Id:      "trsr_one",
					OtherId: "trsr_parent",
					Type:    "sub_resource",
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
		},
		{
			"TestListResourceResponse",
			nil,
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
					{
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
			nil,
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
					{
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
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			handler := func(ctx context.Context, req any) (any, error) {
				require.Empty(t, cmp.Diff(req, tc.expectHandlerReq, protocmp.Transform()))
				return tc.handlerResp, nil
			}

			got, err := subtypes.AttributeTransformerInterceptor(ctx)(ctx, tc.req, nil, handler)
			require.NoError(t, err)
			require.Empty(t, cmp.Diff(got, tc.excpetResp, protocmp.Transform()))
		})
	}
}

func TestAttributeTransformerInterceptorRequestErrors(t *testing.T) {
	cases := []struct {
		name string
		req  any
		want error
	}{
		{
			"InvalidAttributes",
			&attribute.TestCreateResourceRequest{
				Item: &attribute.TestResource{
					Type: "sub_resource",
					Attrs: &attribute.TestResource_Attributes{
						Attributes: func() *structpb.Struct {
							attrs, _ := structpb.NewStruct(map[string]any{
								"foo": "test",
							})
							return attrs
						}(),
					},
				},
			},
			handlers.InvalidArgumentErrorf("Error in provided request.",
				map[string]string{"attributes": "Attribute fields do not match the expected format."}),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			handler := func(ctx context.Context, req any) (any, error) {
				t.Fatalf("handler should not be called")
				return nil, nil
			}

			_, err := subtypes.AttributeTransformerInterceptor(ctx)(ctx, tc.req, nil, handler)
			require.Error(t, err)
			require.ErrorIs(t, err, tc.want)
		})
	}
}
