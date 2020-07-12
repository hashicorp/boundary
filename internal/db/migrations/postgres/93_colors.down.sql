begin;
  delete from iam_scope where public_id not in ('global');
  delete from iam_user where public_id not in ('u_anon', 'u_auth');
  delete from iam_role_grant;
  delete from iam_group;
  delete from iam_role;
commit;
