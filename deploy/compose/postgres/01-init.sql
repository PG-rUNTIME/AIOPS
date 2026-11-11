-- One database per stateful service; least-privilege roles. Passwords come from
-- the environment (docker-entrypoint runs this as the superuser at first start).
CREATE EXTENSION IF NOT EXISTS vector;
\set ON_ERROR_STOP on
SELECT 'CREATE DATABASE router'          WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname='router')\gexec
SELECT 'CREATE DATABASE correlator'      WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname='correlator')\gexec
SELECT 'CREATE DATABASE feedback'        WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname='feedback')\gexec
SELECT 'CREATE DATABASE control_plane'   WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname='control_plane')\gexec
SELECT 'CREATE DATABASE rag'             WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname='rag')\gexec
