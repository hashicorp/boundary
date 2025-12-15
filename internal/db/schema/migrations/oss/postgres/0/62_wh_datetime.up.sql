-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  create table wh_date_dimension (
    id                            integer      primary key,
    date                          date         not null,
    calendar_quarter              wh_dim_text,
    calendar_month                wh_dim_text,
    calendar_year                 smallint     not null,
    day_of_week                   wh_dim_text,
    day_of_week_number            smallint     not null,
    day_of_week_number_iso        smallint     not null,
    day_of_week_number_zero_based smallint     not null,
    day_number_in_calendar_month  smallint     not null,
    day_number_in_calendar_year   smallint     not null,
    weekday_indicator             wh_dim_text
  );

  insert into wh_date_dimension (
    id, date,
    calendar_quarter, calendar_month, calendar_year,
    day_of_week, day_of_week_number, day_of_week_number_iso, day_of_week_number_zero_based,
    day_number_in_calendar_month, day_number_in_calendar_year,
    weekday_indicator
  ) values (
    -1, 'infinity',
    'None', 'None', -1,
    'None', -1, -1, -1,
    -1, -1,
    'None'
  );

  insert into wh_date_dimension
  select to_char(t.day, 'YYYYMMDD')::integer as id,
         t.day::date                         as date,
         'Q' || to_char(t.day, 'Q')          as calendar_quarter,
         to_char(t.day, 'Month')             as calendar_month,
         extract(year from t.day)            as calendar_year,
         to_char(t.day, 'Day')               as day_of_week,
         to_char(t.day, 'D')::int            as day_of_week_number,
         extract(isodow from t.day)          as day_of_week_number_iso,
         extract(dow from t.day)             as day_of_week_number_zero_based,
         extract(day from t.day)             as day_number_in_calendar_month,
         extract(doy from t.day)             as day_number_in_calendar_year,
         case extract(isodow from t.day)
           when 6 then 'Weekend'
           when 7 then 'Weekend'
           else 'Weekday'
         end                                 as weekday_indicator
    from generate_series(
           date_trunc('day', timestamp '2019-10-09'),
           date_trunc('day', timestamp '2019-10-09' + interval '50 years'),
           interval '1 day'
         ) as t(day);

  create table wh_time_of_day_dimension (
    id                 integer      primary key,
    time_no_zone       time         not null,
    time_at_utc        timetz       not null,
    hour_of_day        smallint     not null,
    minute_of_hour     smallint     not null,
    second_of_minute   smallint     not null,
    display_time_24    wh_dim_text,
    display_time_12    wh_dim_text,
    meridiem_indicator wh_dim_text
  );

  set timezone = 'UTC';

  insert into wh_time_of_day_dimension (
    id, time_no_zone, time_at_utc,
    hour_of_day, minute_of_hour, second_of_minute,
    display_time_24, display_time_12, meridiem_indicator
  ) values (
    -1, 'allballs', 'allballs',
    -1, -1, -1,
    'None', 'None', 'None'
  );

  insert into wh_time_of_day_dimension
  select to_char(t.second, 'SSSS')::integer as id,
         t.second::time                     as time_no_zone,
         t.second::time                     as time_at_utc,
         extract(hour from t.second)        as hour_of_day,
         extract(minute from t.second)      as minute_of_hour,
         extract(second from t.second)      as second_of_minute,
         to_char(t.second, 'HH24:MI:SS')    as display_time_24,
         to_char(t.second, 'HH12:MI:SS AM') as display_time_12,
         to_char(t.second, 'PM')            as meridiem_indicator
    from generate_series(
           date_trunc('day', current_timestamp),
           date_trunc('day', current_timestamp) + interval '24 hours' - interval '1 second',
           interval '1 second'
         ) as t(second);

commit;
