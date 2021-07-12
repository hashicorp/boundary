begin;

    create function wt_sub_seconds(sec integer, ts timestamp with time zone)
        returns timestamp with time zone
    as $$
    select ts - sec * '1 second'::interval;
    $$ language sql
        stable
        returns null on null input;
    comment on function wt_add_seconds is
        'wt_sub_seconds returns ts - sec.';

    create function wt_sub_seconds_from_now(sec integer)
        returns timestamp with time zone
    as $$
    select wt_sub_seconds(sec, current_timestamp);
    $$ language sql
        stable
        returns null on null input;
    comment on function wt_add_seconds_to_now is
        'wt_sub_seconds_from_now returns current_timestamp - sec.';

commit;
