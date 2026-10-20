-- Cria papéis, banco e schema do SOC. Idempotente.
-- Executado por setup-postgres.sh como superusuário "postgres".
-- As senhas chegam por variáveis de ambiente (\getenv) para não aparecerem
-- na linha de comando nem no histórico.

\set ON_ERROR_STOP on
SET log_statement = 'none';

\getenv collector_pw SOC_COLLECTOR_PASSWORD
\getenv logstash_pw SOC_LOGSTASH_PASSWORD

SELECT NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'soc_owner') AS create_owner \gset
\if :create_owner
CREATE ROLE soc_owner NOLOGIN;
\endif

SELECT NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'soc_collector') AS create_collector \gset
\if :create_collector
CREATE ROLE soc_collector LOGIN;
\endif

SELECT NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'soc_logstash') AS create_logstash \gset
\if :create_logstash
CREATE ROLE soc_logstash LOGIN;
\endif

ALTER ROLE soc_collector WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE CONNECTION LIMIT 10 PASSWORD :'collector_pw';
ALTER ROLE soc_logstash  WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE CONNECTION LIMIT 5  PASSWORD :'logstash_pw';

SELECT NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'soc') AS create_db \gset
\if :create_db
CREATE DATABASE soc OWNER soc_owner ENCODING 'UTF8' TEMPLATE template0;
\endif

REVOKE ALL ON DATABASE soc FROM PUBLIC;
GRANT CONNECT ON DATABASE soc TO soc_collector, soc_logstash;

-- Limites por papel: protegem o horizonte de xmin usado pela publicação incremental.
ALTER ROLE soc_collector IN DATABASE soc SET search_path = soc;
ALTER ROLE soc_collector IN DATABASE soc SET statement_timeout = '5min';
ALTER ROLE soc_collector IN DATABASE soc SET idle_in_transaction_session_timeout = '2min';
ALTER ROLE soc_collector IN DATABASE soc SET timezone = 'UTC';
ALTER ROLE soc_logstash  IN DATABASE soc SET search_path = soc;
ALTER ROLE soc_logstash  IN DATABASE soc SET statement_timeout = '5min';
ALTER ROLE soc_logstash  IN DATABASE soc SET idle_in_transaction_session_timeout = '2min';
ALTER ROLE soc_logstash  IN DATABASE soc SET timezone = 'UTC';

\connect soc

REVOKE ALL ON SCHEMA public FROM PUBLIC;
CREATE SCHEMA IF NOT EXISTS soc AUTHORIZATION soc_owner;
REVOKE ALL ON SCHEMA soc FROM PUBLIC;
GRANT USAGE ON SCHEMA soc TO soc_collector, soc_logstash;

CREATE TABLE IF NOT EXISTS soc.schema_migrations (
    version    text PRIMARY KEY,
    applied_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE soc.schema_migrations OWNER TO soc_owner;
