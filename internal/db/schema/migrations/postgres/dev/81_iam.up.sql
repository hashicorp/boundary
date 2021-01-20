begin;

-- email is added to the iam_user as an external data point to deduce which user
-- is being represented by the iam_user.
alter table iam_user
add column email wt_email; -- intentionally, can be null and not unique

commit;