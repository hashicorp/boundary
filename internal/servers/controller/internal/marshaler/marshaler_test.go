package marshaler_test

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/internal/gen/testing/attribute"
	"github.com/hashicorp/boundary/internal/servers/controller/internal/marshaler"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestDecode(t *testing.T) {
	cases := []struct {
		name     string
		newGot   func() interface{}
		expected interface{}
	}{
		{
			"TestResourceSubResource",
			func() interface{} { return &attribute.TestResource{} },
			&attribute.TestResource{
				Id:   "one",
				Type: "sub_resource",
				Attrs: &attribute.TestResource_SubResourceAttributes{
					SubResourceAttributes: &attribute.TestSubResourceAttributes{
						Name: "test",
					},
				},
			},
		},
		{
			"TestResourceSubResource/DoublePointer",
			func() interface{} {
				a := &attribute.TestResource{}
				return &a
			},
			func() interface{} {
				a := &attribute.TestResource{
					Id:   "one",
					Type: "sub_resource",
					Attrs: &attribute.TestResource_SubResourceAttributes{
						SubResourceAttributes: &attribute.TestSubResourceAttributes{
							Name: "test",
						},
					},
				}
				return &a
			}(),
		},
		{
			"TestResourceDefault",
			func() interface{} { return &attribute.TestResource{} },
			func() interface{} {
				attrs, _ := structpb.NewStruct(map[string]interface{}{
					"field1": "val1",
					"field2": "val2",
				})
				return &attribute.TestResource{
					Id:   "two",
					Type: "default",
					Attrs: &attribute.TestResource_Attributes{
						Attributes: attrs,
					},
				}
			}(),
		},
		{
			"TestResourceUnknown",
			func() interface{} { return &attribute.TestResource{} },
			func() interface{} {
				attrs, _ := structpb.NewStruct(map[string]interface{}{
					"field1": "val1",
					"field2": "val2",
				})
				return &attribute.TestResource{
					Id:   "two",
					Type: "unknown",
					Attrs: &attribute.TestResource_Attributes{
						Attributes: attrs,
					},
				}
			}(),
		},
		{
			"TestNoOneOf",
			func() interface{} { return &attribute.TestNoOneOf{} },
			func() interface{} {
				attrs, _ := structpb.NewStruct(map[string]interface{}{
					"field1": "val1",
					"field2": "val2",
				})
				return &attribute.TestNoOneOf{
					Id:         "three",
					Type:       "sub_resource",
					Attributes: attrs,
				}
			}(),
		},
		{
			"TestListResourceResponse",
			func() interface{} { return &attribute.TestListResourceResponse{} },
			func() interface{} {
				attrs, _ := structpb.NewStruct(map[string]interface{}{
					"field1": "val1",
					"field2": "val2",
				})
				return &attribute.TestListResourceResponse{
					Items: []*attribute.TestResource{
						{
							Id:   "one",
							Type: "sub_resource",
							Attrs: &attribute.TestResource_SubResourceAttributes{
								SubResourceAttributes: &attribute.TestSubResourceAttributes{
									Name: "test",
								},
							},
						},
						{
							Id:   "two",
							Type: "default",
							Attrs: &attribute.TestResource_Attributes{
								Attributes: attrs,
							},
						},
						{
							Id:   "three",
							Type: "unknown",
							Attrs: &attribute.TestResource_Attributes{
								Attributes: attrs,
							},
						},
					},
				}
			}(),
		},
		{
			"TestListResourceResponse/DoublePointer",
			func() interface{} {
				a := &attribute.TestListResourceResponse{}
				return &a
			},
			func() interface{} {
				attrs, _ := structpb.NewStruct(map[string]interface{}{
					"field1": "val1",
					"field2": "val2",
				})
				a := &attribute.TestListResourceResponse{
					Items: []*attribute.TestResource{
						{
							Id:   "one",
							Type: "sub_resource",
							Attrs: &attribute.TestResource_SubResourceAttributes{
								SubResourceAttributes: &attribute.TestSubResourceAttributes{
									Name: "test",
								},
							},
						},
						{
							Id:   "two",
							Type: "default",
							Attrs: &attribute.TestResource_Attributes{
								Attributes: attrs,
							},
						},
						{
							Id:   "three",
							Type: "unknown",
							Attrs: &attribute.TestResource_Attributes{
								Attributes: attrs,
							},
						},
					},
				}
				return &a
			}(),
		},
	}

	for _, tc := range cases {
		t.Run("Decoder/"+tc.name, func(t *testing.T) {
			input, err := os.Open(fmt.Sprintf("testdata/decode/%s.json", tc.name))
			require.NoError(t, err)
			t.Cleanup(func() { input.Close() })

			m := marshaler.New()

			decoder := m.NewDecoder(input)

			got := tc.newGot()
			err = decoder.Decode(got)
			require.NoError(t, err)

			assert.Empty(t, cmp.Diff(got, tc.expected, protocmp.Transform()))
		})
	}

	for _, tc := range cases {
		t.Run("Unmarshal/"+tc.name, func(t *testing.T) {
			input, err := ioutil.ReadFile(fmt.Sprintf("testdata/decode/%s.json", tc.name))
			require.NoError(t, err)

			m := marshaler.New()

			got := tc.newGot()
			err = m.Unmarshal(input, got)
			require.NoError(t, err)

			assert.Empty(t, cmp.Diff(got, tc.expected, protocmp.Transform()))
		})
	}
}

func TestEncode(t *testing.T) {
	cases := []struct {
		name string
		v    interface{}
	}{
		{
			"TestResourceSubResource",
			&attribute.TestResource{
				Id:   "one",
				Type: "sub_resource",
				Attrs: &attribute.TestResource_SubResourceAttributes{
					SubResourceAttributes: &attribute.TestSubResourceAttributes{
						Name: "test",
					},
				},
			},
		},
		{
			"TestResourceDefault",
			func() interface{} {
				attrs, _ := structpb.NewStruct(map[string]interface{}{
					"field1": "val1",
					"field2": "val2",
				})
				return &attribute.TestResource{
					Id:   "two",
					Type: "default",
					Attrs: &attribute.TestResource_Attributes{
						Attributes: attrs,
					},
				}
			}(),
		},
		{
			"TestResourceUnknown",
			func() interface{} {
				attrs, _ := structpb.NewStruct(map[string]interface{}{
					"field1": "val1",
					"field2": "val2",
				})
				return &attribute.TestResource{
					Id:   "two",
					Type: "unknown",
					Attrs: &attribute.TestResource_Attributes{
						Attributes: attrs,
					},
				}
			}(),
		},
		{
			"TestNoOneOf",
			func() interface{} {
				attrs, _ := structpb.NewStruct(map[string]interface{}{
					"field1": "val1",
					"field2": "val2",
				})
				return &attribute.TestNoOneOf{
					Id:         "three",
					Type:       "sub_resource",
					Attributes: attrs,
				}
			}(),
		},
		{
			"TestListResourceResponse",
			func() interface{} {
				attrs, _ := structpb.NewStruct(map[string]interface{}{
					"field1": "val1",
					"field2": "val2",
				})
				return &attribute.TestListResourceResponse{
					Items: []*attribute.TestResource{
						{
							Id:   "one",
							Type: "sub_resource",
							Attrs: &attribute.TestResource_SubResourceAttributes{
								SubResourceAttributes: &attribute.TestSubResourceAttributes{
									Name: "test",
								},
							},
						},
						{
							Id:   "two",
							Type: "default",
							Attrs: &attribute.TestResource_Attributes{
								Attributes: attrs,
							},
						},
						{
							Id:   "three",
							Type: "unknown",
							Attrs: &attribute.TestResource_Attributes{
								Attributes: attrs,
							},
						},
					},
				}
			}(),
		},
	}

	for _, tc := range cases {
		t.Run("Encoder/"+tc.name, func(t *testing.T) {
			expect, err := ioutil.ReadFile(fmt.Sprintf("testdata/encode/%s.json", tc.name))
			require.NoError(t, err)

			var buf bytes.Buffer
			m := marshaler.New()

			enc := m.NewEncoder(&buf)
			err = enc.Encode(tc.v)
			require.NoError(t, err)

			assert.JSONEq(t, string(expect), buf.String())
		})
	}

	for _, tc := range cases {
		t.Run("Marshal/"+tc.name, func(t *testing.T) {
			expect, err := ioutil.ReadFile(fmt.Sprintf("testdata/encode/%s.json", tc.name))
			require.NoError(t, err)

			m := marshaler.New()

			b, err := m.Marshal(tc.v)
			require.NoError(t, err)

			assert.JSONEq(t, string(expect), string(b))
		})
	}
}
