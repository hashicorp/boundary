package main_test

// TODO: Reenable once we reimplement generation of As functions once static hosts lands
/*
func TestDetailTemplating(t *testing.T) {
	lt := time.Now()
	c := hosts.HostCatalog{
		Id:          "id",
		CreatedTime: lt,
		Attributes: map[string]interface{}{
			"regions":    []string{"a", "b"},
			"access_key": "access",
			"secret_key": "secret",
			"rotate":     true,
		},
	}

	ac, err := c.AsAwsEc2HostCatalog()
	assert.NoError(t, err)
	assert.Equal(t, &hosts.AwsEc2HostCatalog{
		HostCatalog: &c,
		Regions:     []string{"a", "b"},
		AccessKey:   api.String("access"),
		SecretKey:   api.String("secret"),
		Rotate:      api.Bool(true),
	}, ac)
}
*/
