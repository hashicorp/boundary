-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

-- For use in testing session_state transitions
insert into session_state
(session_id, state)
values
    ('s1_____cindy','terminated'),
    ('s1_____ciara','canceling'),
    ('s1_____carly','active');

commit;