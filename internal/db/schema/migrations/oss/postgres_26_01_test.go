package oss_test

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/common"
	"github.com/hashicorp/boundary/internal/db/schema"
	"github.com/hashicorp/boundary/testing/dbtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMigrations_WareHouse_HostAddresses(t *testing.T) {
	const (
		priorMigration   = 25001
		currentMigration = 26001
	)

	t.Parallel()
	ctx := context.Background()
	dialect := dbtest.Postgres

	c, u, _, err := dbtest.StartUsingTemplate(dialect, dbtest.WithTemplate(dbtest.Template1))
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, c())
	})
	d, err := common.SqlOpen(dialect, u)
	require.NoError(t, err)

	// migration to the prior migration (before the one we want to test)
	m, err := schema.NewManager(ctx, schema.Dialect(dialect), d, schema.WithEditions(
		schema.TestCreatePartialEditions(schema.Dialect(dialect), schema.PartialEditions{"oss": priorMigration}),
	))
	require.NoError(t, err)

	require.NoError(t, m.ApplyMigrations(ctx))
	state, err := m.CurrentState(ctx)
	require.NoError(t, err)
	want := &schema.State{
		Initialized: true,
		Editions: []schema.EditionState{
			{
				Name:                  "oss",
				BinarySchemaVersion:   priorMigration,
				DatabaseSchemaVersion: priorMigration,
				DatabaseSchemaState:   schema.Equal,
			},
		},
	}
	require.Equal(t, want, state)

	// get a connection
	dbType, err := db.StringToDbType(dialect)
	require.NoError(t, err)
	conn, err := db.Open(ctx, dbType, u)
	require.NoError(t, err)
	rw := db.New(conn)

	type whAddress struct {
		Address                   string
		AddressType               string
		IpAddressFamily           string
		PrivateIpAddressIndicator string
		DnsName                   string
		Ip4Address                string
		Ip6Address                string
	}
	addresses := []whAddress{
		{
			Address:                   "10.0.0.1",
			AddressType:               "IP Address",
			IpAddressFamily:           "IPv4",
			PrivateIpAddressIndicator: "Private IP address",
			DnsName:                   "Not Applicable",
			Ip4Address:                "10.0.0.1",
			Ip6Address:                "Not Applicable",
		},
		{
			Address:                   "12.3.4.5",
			AddressType:               "IP Address",
			IpAddressFamily:           "IPv4",
			PrivateIpAddressIndicator: "Public IP address",
			DnsName:                   "Not Applicable",
			Ip4Address:                "12.3.4.5",
			Ip6Address:                "Not Applicable",
		},
		{
			Address:                   "fe80::1234:5678:1234:5678",
			AddressType:               "IP Address",
			IpAddressFamily:           "IPv6",
			PrivateIpAddressIndicator: "Private IP address",
			DnsName:                   "Not Applicable",
			Ip4Address:                "Not Applicable",
			Ip6Address:                "fe80::1234:5678:1234:5678",
		},
		{
			Address:                   "2001:4860:4860::8888",
			AddressType:               "IP Address",
			IpAddressFamily:           "IPv6",
			PrivateIpAddressIndicator: "Public IP address",
			DnsName:                   "Not Applicable",
			Ip4Address:                "Not Applicable",
			Ip6Address:                "2001:4860:4860::8888",
		},
		{
			Address:                   "foo",
			AddressType:               "DNS Name",
			IpAddressFamily:           "Not Applicable",
			PrivateIpAddressIndicator: "Not Applicable",
			DnsName:                   "foo",
			Ip4Address:                "Not Applicable",
			Ip6Address:                "Not Applicable",
		},
		{
			Address:                   "something.com",
			AddressType:               "DNS Name",
			IpAddressFamily:           "Not Applicable",
			PrivateIpAddressIndicator: "Not Applicable",
			DnsName:                   "something.com",
			Ip4Address:                "Not Applicable",
			Ip6Address:                "Not Applicable",
		},
		{
			Address:                   "10.0.foo.com",
			AddressType:               "DNS Name",
			IpAddressFamily:           "Not Applicable",
			PrivateIpAddressIndicator: "Not Applicable",
			DnsName:                   "10.0.foo.com",
			Ip4Address:                "Not Applicable",
			Ip6Address:                "Not Applicable",
		},
		{
			Address:                   "not valid anything",
			AddressType:               "DNS Name",
			IpAddressFamily:           "Not Applicable",
			PrivateIpAddressIndicator: "Not Applicable",
			DnsName:                   "not valid anything",
			Ip4Address:                "Not Applicable",
			Ip6Address:                "Not Applicable",
		},
		{
			Address:                   "Unsupported",
			AddressType:               "Unknown",
			IpAddressFamily:           "Not Applicable",
			PrivateIpAddressIndicator: "Not Applicable",
			DnsName:                   "Not Applicable",
			Ip4Address:                "Not Applicable",
			Ip6Address:                "Not Applicable",
		},
		{
			Address:                   "Unknown",
			AddressType:               "Unknown",
			IpAddressFamily:           "Not Applicable",
			PrivateIpAddressIndicator: "Not Applicable",
			DnsName:                   "Not Applicable",
			Ip4Address:                "Not Applicable",
			Ip6Address:                "Not Applicable",
		},
	}
	{
		q := `
insert into wh_host_dimension
(host_id, host_type, host_name, host_description, host_address,
host_set_id, host_set_type, host_set_name, host_set_description,
host_catalog_id, host_catalog_type, host_catalog_name, host_catalog_description,
target_id, target_type, target_name, target_description, target_default_port_number,
target_session_max_seconds, target_session_connection_limit,
project_id, project_name, project_description,
organization_id, organization_name, organization_description,
current_row_indicator, row_effective_time, row_expiration_time)
values
('h_1234567890', 'static', 'None', 'None', ?,
'hs_1234567890', 'static', 'None', 'None',
'hc_1234567890', 'static', 'None', 'None',
't_1234567890', 'tcp', 'None', 'None', 0,
30, 1,
'p_1234567890', 'None', 'None',
'o_1234567890', 'None', 'None',
'Expired', current_timestamp, current_timestamp)
`
		for _, a := range addresses {
			_, err := rw.Exec(ctx, q, []interface{}{a.Address})
			require.NoError(t, err)
		}
		// Duplicate a few records...
		_, err := rw.Exec(ctx, q, []interface{}{addresses[1].Address})
		require.NoError(t, err)
		_, err = rw.Exec(ctx, q, []interface{}{addresses[5].Address})
		require.NoError(t, err)
	}

	// now we're ready for the migration we want to test.
	m, err = schema.NewManager(ctx, schema.Dialect(dialect), d, schema.WithEditions(
		schema.TestCreatePartialEditions(schema.Dialect(dialect), schema.PartialEditions{"oss": currentMigration}),
	))
	require.NoError(t, err)

	require.NoError(t, m.ApplyMigrations(ctx))
	state, err = m.CurrentState(ctx)
	require.NoError(t, err)
	want = &schema.State{
		Initialized: true,
		Editions: []schema.EditionState{
			{
				Name:                  "oss",
				BinarySchemaVersion:   currentMigration,
				DatabaseSchemaVersion: currentMigration,
				DatabaseSchemaState:   schema.Equal,
			},
		},
	}
	require.Equal(t, want, state)
	// Now read all the converted rows and see if we have transformed and
	// calculated the values as expected.
	{
		rows, err := rw.Query(ctx, "select * from wh_network_address_dimension", nil)
		require.NoError(t, err)
		var results []whAddress
		for rows.Next() {
			var addr whAddress
			require.NoError(t, rw.ScanRows(context.Background(), rows, &addr))
			results = append(results, addr)
		}
		assert.ElementsMatch(t, results, addresses)
	}
}
