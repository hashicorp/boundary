package handlers

import (
	"testing"

	pb "github.com/hashicorp/boundary/internal/gen/controller/protooptions"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMaskManager(t *testing.T) {
	mm, err := NewMaskManager(&pb.TestBase{}, &pb.TestProperlyNamedFields{})
	require.NoError(t, err)
	assert.Equal(t, []string(nil), mm.Translate([]string{"doesnt_exist"}))
	assert.Equal(t, []string{"OtherFirstField"}, mm.Translate([]string{"first_field"}))
	assert.Equal(t, []string{"OtherFirstField"}, mm.Translate([]string{"first_field", "doesnt_exist"}))
	assert.Equal(t, []string(nil), mm.Translate([]string{"FiRsT_fIeLd"}))
	assert.Equal(t, []string{"other_second_field"}, mm.Translate([]string{"strangly_formatted_field"}))
	assert.Equal(t, []string{"other_second_field", "other_field_3"}, mm.Translate([]string{"strangly_formatted_field", "field3"}))
}

func TestMaskManager_errors(t *testing.T) {
	_, err := NewMaskManager(&pb.TestBase{}, &pb.TestManyToOneMappings{})
	assert.Error(t, err)
	_, err = NewMaskManager(&pb.TestBase{}, &pb.TestNameDoesntMap{})
	assert.Error(t, err)
	_, err = NewMaskManager(&pb.TestBase{}, &pb.TestNotEnoughFields{})
	assert.Error(t, err)
}
