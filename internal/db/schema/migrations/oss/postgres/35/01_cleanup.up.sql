begin;

-- This adds additional cleanup to what went into 0.8.x. A forgotten case could
-- mean that sessions can persist in canceled state even if there are no
-- connections for that session (possibly due to cleanup) and will never be
-- transitioned because connection state cannot be determined.
--
-- There is no reason to transition to terminated state as we remove those
-- periodically anyways, and there is no useful information to be gleaned from
-- having it in that state.
--
-- Note that this only cleans up those in canceling state. In pending we may
-- well not have connections yet; in active our fixed logic should ensure that
-- when it transitions the right things happen; and in terminated those will be
-- cleaned up periodically.
delete from session
where public_id not in 
  (select session_id from session_connection)
and
  termination_reason = 'canceled';

commit;