// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package billing

const (
	activeUsersLastTwoMonthsQuery = `
select *
  from hcp_billing_monthly_active_users_last_2_months();
`
	activeUsersWithStartTimeQuery = `
select *
  from hcp_billing_monthly_active_users_all(@start_time);
`
	activeUsersWithStartTimeAndEndTimeQuery = `
select *
  from hcp_billing_monthly_active_users_all(@start_time, @end_time);
`
)
