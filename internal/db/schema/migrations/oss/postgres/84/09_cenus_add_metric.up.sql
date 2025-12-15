-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
  -- Create enum table for valid cenus metrics.
  create table census_metric_enm (
    name text primary key
    constraint only_predefined_census_metrics_allowed
    check (
      name in (
        'sessions',
        'active_users'
      )
    )
  );
  comment on table census_metric_enm is
    'census_metric_enm is an enumeration table for census metric types.';

  insert into census_metric_enm
              (name)
       values ('sessions'),
              ('active_users');

  -- Drop constraint and index from 72/01_census.up.sql
  drop index census_last_uploaded_one_row;
  alter table census_last_uploaded drop constraint census_last_uploaded_pkey;

  -- Add new column and populate the default value.
  alter table census_last_uploaded
   add column metric text
              default 'sessions'
              not null
              primary key
              constraint census_metric_enm_fkey
                references census_metric_enm (name)
                on delete restrict
                on update restrict;
  alter table census_last_uploaded alter column metric drop default;
  comment on table census_last_uploaded is
    'census_last_uploaded is a table which contains the timestamp '
    'of the last time census data was uploaded, per census metric.';

  -- Add new row for active_users.
  insert into census_last_uploaded
              (last_uploaded_at,         metric)
       values ('-infinity'::timestamptz, 'active_users');
commit;
