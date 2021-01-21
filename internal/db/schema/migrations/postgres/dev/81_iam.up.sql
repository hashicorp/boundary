begin;

-- email is added to the iam_user as an external data point to deduce which user
-- is being represented by the iam_user.
alter table iam_user
add column email wt_email, -- intentionally, can be null and not unique
add column wt_name text;

alter table iam_user
rename column name to resource_name;  -- disambiguate name 

alter table iam_user                 
rename column description to resource_description; -- disambiguate description

commit;