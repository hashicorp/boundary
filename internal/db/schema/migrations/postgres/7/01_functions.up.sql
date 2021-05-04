begin;

    create function wt_add_seconds(sec integer, ts timestamp with time zone)
        returns timestamp with time zone
    as $$
    select ts + sec * '1 second'::interval;
    $$ language sql
        stable
        returns null on null input;
    comment on function wt_add_seconds is
        'wt_add_seconds returns ts + sec.';

    create function wt_add_seconds_to_now(sec integer)
        returns timestamp with time zone
    as $$
    select wt_add_seconds(sec, current_timestamp);
    $$ language sql
        stable
        returns null on null input;
    comment on function wt_add_seconds_to_now is
        'wt_add_seconds_to_now returns current_timestamp + sec.';

commit;
