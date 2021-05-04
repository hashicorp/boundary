begin;

drop view job_jobs_to_run;

delete from oplog_ticket
where name in ('job',
               'job_run');

drop table job_run;
drop table job_run_status_enm;
drop table job;
drop table job_plugin;

commit;
