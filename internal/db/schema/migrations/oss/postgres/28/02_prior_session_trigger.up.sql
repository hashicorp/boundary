-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

-- Drop prior session state trigger; to be replaced with logic added to insert_session_state()
drop trigger update_session_state on session_state;
drop function update_prior_session_state();

-- Remove invalid session transitions lingering in the DB

-- Create a temp table to classify session states by number of transitions
create temp table state_counts as
select count(*), session_id from session_state group by session_id;

-- Remove bad states for session ids with 4 states. Remove states added after 'terminated' to remove
-- invalid transitions that occurred after the session terminated
-- Ex: PATC, PTAC, PCTA, PTCA, pruned to valid transitions PAT, PT, PCT, PT
do $$
declare
    target record;
begin
    for target in select session_id from state_counts where count = 4 loop
        -- If the last state is not terminated for this session...
        if (select state from session_state where session_id in
            (select session_id from state_counts where count = 4)
            and session_id=target.session_id order by start_time desc limit 1)
            != 'terminated' then
            -- Prune invalid states after the session terminated
            delete from session_state where session_id = target.session_id and previous_end_time >(
                select previous_end_time from session_state where session_id=target.session_id and state='terminated');
            -- Then remove terminated end time
            update session_state set end_time=NULL where session_id=target.session_id and state='terminated';
        end if;
    end loop;
end; $$;

-- Remove bad states for session ids with 3 states, similar to the above
-- Difference from above is the need to check if terminated exists in the set of states
-- Ex: PTA, PTC -> pruned to PT, PT
-- Additional check for state PCA, pruned to PC
-- Valid transitions like PAT, PCT, and in progress sessions like PAC will be ignored
do $$
declare
    target record;
begin
    for target in select session_id from state_counts where count = 3 loop
        -- If the last state is not terminated for this session...
        if (select state from session_state where session_id in
            (select session_id from state_counts where count = 3)
            and session_id=target.session_id order by start_time desc limit 1)
            != 'terminated' then
            -- See if terminated appears; if so, prune back to it
            if exists(select * from session_state where session_id=target.session_id and state='terminated')then
                --Then we find the terminated record and timestamp and delete those that came before
                delete from session_state where session_id = target.session_id and previous_end_time >(
                    select previous_end_time from session_state where session_id=target.session_id and state='terminated');
                -- Then remove terminated end time
                update session_state set end_time=NULL where session_id=target.session_id and state='terminated';
            end if;
        end if;
        -- Check for PCA case; if last state is not cancelled but canceling appears in the states
        if (select state from session_state where session_id in
            (select session_id from state_counts where count = 3)
            and session_id=target.session_id order by start_time desc limit 1)
            != 'canceling' then
            -- See if canceling appears; if so, prune back to it
            if exists(select * from session_state where session_id=target.session_id and state='canceling')then
                --Then we find the canceling record and timestamp and delete those that came before
                delete from session_state where session_id = target.session_id and previous_end_time >(
                    select previous_end_time from session_state where session_id=target.session_id and state='canceling');
                -- Then remove canceling end time
                update session_state set end_time=NULL where session_id=target.session_id and state='canceling';
            end if;
        end if;
    end loop;
end; $$;

-- Replaces trigger from 0/50_session.up.sql
-- Replaced in 92/02_session_state_tstzrange.up.sql
-- Update insert session state transition trigger
drop trigger insert_session_state on session_state;
drop function insert_session_state();

create function insert_session_state() returns trigger
as $$
declare
    old_col_state text;
begin
    update session_state
    set end_time = now()
    where (session_id = new.session_id
        and end_time is null) returning state into old_col_state;
    new.prior_state= old_col_state;

    if not found then
        new.previous_end_time = null;
        new.start_time = now();
        new.end_time = null;
        new.prior_state='pending';
        return new;
    end if;

    new.previous_end_time = now();
    new.start_time = now();
    new.end_time = null;

    return new;

end;
$$ language plpgsql;

create trigger insert_session_state before insert on session_state
    for each row execute procedure insert_session_state();

commit;
