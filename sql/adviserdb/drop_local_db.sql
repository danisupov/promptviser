SELECT pg_terminate_backend (pg_stat_activity.pid)
FROM pg_stat_activity
WHERE
    pg_stat_activity.datname = 'adviserdb'
    AND pid <> pg_backend_pid ();

DROP DATABASE IF EXISTS adviserdb;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'promptviser') THEN
        EXECUTE 'REVOKE ALL ON SCHEMA public FROM promptviser';
    END IF;
END $$;

DROP USER IF EXISTS promptviser;

DROP ROLE IF EXISTS adviser;

\list \dn