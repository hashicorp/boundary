// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package subtypes

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/internal/gen/testing/attribute"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestFilterable(t *testing.T) {
	cases := []struct {
		name string
		item proto.Message
		want proto.Message
	}{
		{
			"TestResource/sub_resource",
			&attribute.TestResource{
				Type: "sub_resource",
				Attrs: &attribute.TestResource_SubResourceAttributes{
					SubResourceAttributes: &attribute.TestSubResourceAttributes{
						Name: "test",
					},
				},
			},
			func() *structpb.Struct {
				w, _ := structpb.NewStruct(map[string]any{
					"type": "sub_resource",
					"attributes": map[string]any{
						"name": "test",
					},
				})
				return w
			}(),
		},
		{
			"TestResource/default",
			&attribute.TestResource{
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
			func() *structpb.Struct {
				w, _ := structpb.NewStruct(map[string]any{
					"type": "default",
					"attributes": map[string]any{
						"name": "test",
					},
				})
				return w
			}(),
		},
		{
			"TestNoOneOf",
			&attribute.TestNoOneOf{
				Type: "sub_resource",
				Attributes: func() *structpb.Struct {
					attrs, _ := structpb.NewStruct(map[string]any{
						"name": "test",
					})
					return attrs
				}(),
			},
			&attribute.TestNoOneOf{
				Type: "sub_resource",
				Attributes: func() *structpb.Struct {
					attrs, _ := structpb.NewStruct(map[string]any{
						"name": "test",
					})
					return attrs
				}(),
			},
		},
		{
			"TestNoAttributes",
			&attribute.TestNoAttributes{
				Id:   "test",
				Type: "no_attr",
			},
			&attribute.TestNoAttributes{
				Id:   "test",
				Type: "no_attr",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Filterable(context.Background(), tc.item)
			require.NoError(t, err)
			require.Empty(t, cmp.Diff(got, tc.want, protocmp.Transform()))
		})
	}
}
