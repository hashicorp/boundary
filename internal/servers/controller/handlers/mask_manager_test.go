package handlers

import (
	"testing"

	pb "github.com/hashicorp/boundary/sdk/pbs/controller/protooptions"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMaskManager(t *testing.T) {
	mm, err := NewMaskManager(MaskDestination{&pb.TestProperlyNamedFields{}}, MaskSource{&pb.TestBase{}})
	require.NoError(t, err)
	assert.Equal(t, []string(nil), mm.Translate([]string{"doesnt_exist"}))
	assert.Equal(t, []string{"OtherFirstField"}, mm.Translate([]string{"first_field"}))
	assert.Equal(t, []string{"OtherFirstField"}, mm.Translate([]string{"first_field", "doesnt_exist"}))
	assert.Equal(t, []string(nil), mm.Translate([]string{"FiRsT_fIeLd"}))
	assert.Equal(t, []string{"other_second_field"}, mm.Translate([]string{"strangly_formatted_field"}))
	assert.Equal(t, []string{"other_second_field", "other_field_3"}, mm.Translate([]string{"strangly_formatted_field", "field3"}))
}

func TestMaskManager_Split(t *testing.T) {
	mm, err := NewMaskManager(MaskDestination{&pb.TestProperlyNamedFields{}}, MaskSource{&pb.TestBaseSplit1{}, &pb.TestBaseSplit2{}})
	require.NoError(t, err)
	assert.Equal(t, []string(nil), mm.Translate([]string{"doesnt_exist"}))
	assert.Equal(t, []string{"OtherFirstField"}, mm.Translate([]string{"first_field"}))
	assert.Equal(t, []string{"OtherFirstField"}, mm.Translate([]string{"first_field", "doesnt_exist"}))
	assert.Equal(t, []string(nil), mm.Translate([]string{"FiRsT_fIeLd"}))
	assert.Equal(t, []string{"other_second_field"}, mm.Translate([]string{"strangly_formatted_field"}))
	assert.Equal(t, []string{"other_second_field", "other_field_3"}, mm.Translate([]string{"strangly_formatted_field", "field3"}))
}

func TestMaskManager_errors(t *testing.T) {
	_, err := NewMaskManager(MaskDestination{&pb.TestBase{}}, MaskSource{&pb.TestManyToOneMappings{}})
	assert.Error(t, err)
	_, err = NewMaskManager(MaskDestination{&pb.TestBase{}}, MaskSource{&pb.TestNameDoesntMap{}})
	assert.Error(t, err)
	_, err = NewMaskManager(MaskDestination{&pb.TestBase{}}, MaskSource{&pb.TestNotEnoughFields{}})
	assert.Error(t, err)
}
