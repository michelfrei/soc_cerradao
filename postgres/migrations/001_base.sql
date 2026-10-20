-- 001: estruturas base da coleta, histórico e publicação.
-- Executada por migrate.sh com SET ROLE soc_owner, em transação única.

-- Controle da coleta ---------------------------------------------------------

CREATE TABLE soc.collector_checkpoint (
    source     text PRIMARY KEY,
    watermark  timestamptz NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE soc.collector_run (
    id           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    source       text NOT NULL,
    started_at   timestamptz NOT NULL DEFAULT now(),
    finished_at  timestamptz,
    status       text NOT NULL CHECK (status IN ('running', 'success', 'failed')),
    window_start timestamptz,
    window_end   timestamptz,
    fetched      integer NOT NULL DEFAULT 0,
    inserted     integer NOT NULL DEFAULT 0,
    changed      integer NOT NULL DEFAULT 0,
    api_calls    integer NOT NULL DEFAULT 0,
    throttled    integer NOT NULL DEFAULT 0,
    error        text
);
CREATE INDEX collector_run_source_started_idx ON soc.collector_run (source, started_at DESC);

-- Eventos de Advanced Hunting (particionados por mês, em UTC) ----------------

CREATE TABLE soc.raw_event (
    event_key    text        NOT NULL,
    occurred_at  timestamptz NOT NULL,
    source       text        NOT NULL,
    table_name   text        NOT NULL,
    device_id    text,
    device_name  text,
    action_type  text,
    collected_at timestamptz NOT NULL DEFAULT now(),
    payload      jsonb       NOT NULL,
    PRIMARY KEY (event_key, occurred_at)
) PARTITION BY RANGE (occurred_at);

CREATE INDEX raw_event_table_time_idx ON soc.raw_event (table_name, occurred_at);

-- Cria as partições mensais que cobrem o intervalo informado.
-- SECURITY DEFINER: o coletor não precisa de privilégio de DDL.
CREATE FUNCTION soc.ensure_raw_event_partitions(p_from timestamptz, p_to timestamptz)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, soc
AS $$
DECLARE
    m    date;
    last date;
    part text;
BEGIN
    IF p_from IS NULL OR p_to IS NULL OR p_to < p_from THEN
        RAISE EXCEPTION 'intervalo inválido: % a %', p_from, p_to;
    END IF;
    IF p_to - p_from > interval '400 days' THEN
        RAISE EXCEPTION 'intervalo maior que 400 dias: % a %', p_from, p_to;
    END IF;

    -- Serializa criações concorrentes de partições.
    PERFORM pg_advisory_xact_lock(hashtext('soc.raw_event.partitions'));

    m    := date_trunc('month', p_from AT TIME ZONE 'UTC')::date;
    last := date_trunc('month', p_to   AT TIME ZONE 'UTC')::date;
    WHILE m <= last LOOP
        part := format('raw_event_y%sm%s', to_char(m, 'YYYY'), to_char(m, 'MM'));
        IF to_regclass(format('soc.%I', part)) IS NULL THEN
            EXECUTE format(
                'CREATE TABLE soc.%I PARTITION OF soc.raw_event FOR VALUES FROM (%L) TO (%L)',
                part,
                (m::timestamp AT TIME ZONE 'UTC'),
                ((m + interval '1 month')::timestamp AT TIME ZONE 'UTC'));
        END IF;
        m := (m + interval '1 month')::date;
    END LOOP;
END;
$$;
REVOKE ALL ON FUNCTION soc.ensure_raw_event_partitions(timestamptz, timestamptz) FROM PUBLIC;

-- Incidentes e alertas: estado atual e versões observadas --------------------

CREATE TABLE soc.security_object (
    kind            text        NOT NULL CHECK (kind IN ('incident', 'alert')),
    id              text        NOT NULL,
    title           text,
    status          text,
    severity        text,
    classification  text,
    determination   text,
    assigned_to     text,
    service_source  text,
    incident_id     text,
    web_url         text,
    created_at      timestamptz,
    last_update_at  timestamptz NOT NULL,
    payload_hash    text        NOT NULL,
    payload         jsonb       NOT NULL,
    first_seen_at   timestamptz NOT NULL DEFAULT now(),
    last_changed_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (kind, id)
);
CREATE INDEX security_object_update_idx ON soc.security_object (kind, last_update_at DESC);
CREATE INDEX security_object_incident_idx ON soc.security_object (incident_id) WHERE incident_id IS NOT NULL;

CREATE TABLE soc.security_object_version (
    kind           text        NOT NULL,
    id             text        NOT NULL,
    payload_hash   text        NOT NULL,
    last_update_at timestamptz NOT NULL,
    collected_at   timestamptz NOT NULL DEFAULT now(),
    payload        jsonb       NOT NULL,
    PRIMARY KEY (kind, id, payload_hash),
    FOREIGN KEY (kind, id) REFERENCES soc.security_object (kind, id)
);

-- Publicação incremental para o Logstash --------------------------------------
-- txid identifica a transação que gravou a linha. O Logstash só lê transações
-- com txid abaixo do xmin do snapshot atual, ou seja, já encerradas; todas as
-- linhas de uma mesma transação ficam visíveis juntas. Assim a leitura
-- incremental não pula registros confirmados fora de ordem (ver docs/DECISOES.md).

CREATE TABLE soc.publication (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    txid        xid8        NOT NULL DEFAULT pg_current_xact_id(),
    entity      text        NOT NULL CHECK (entity IN ('event', 'incident', 'incident_version', 'alert', 'alert_version')),
    dataset     text        NOT NULL,
    doc_id      text        NOT NULL,
    occurred_at timestamptz NOT NULL,
    payload     jsonb       NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX publication_txid_idx ON soc.publication (txid);
CREATE INDEX publication_created_idx ON soc.publication (created_at);

-- Republica eventos já retidos no PostgreSQL (reindexação de um período).
CREATE FUNCTION soc.republish_events(p_table text, p_from timestamptz, p_to timestamptz)
RETURNS bigint
LANGUAGE sql
SET search_path = pg_catalog, soc
AS $$
    WITH ins AS (
        INSERT INTO soc.publication (entity, dataset, doc_id, occurred_at, payload)
        SELECT 'event', lower(e.table_name), e.event_key, e.occurred_at, e.payload
        FROM soc.raw_event e
        WHERE e.table_name = p_table
          AND e.occurred_at >= p_from
          AND e.occurred_at <  p_to
        RETURNING 1
    )
    SELECT count(*) FROM ins;
$$;
REVOKE ALL ON FUNCTION soc.republish_events(text, timestamptz, timestamptz) FROM PUBLIC;

-- Remove publicações antigas já lidas (o Logstash avança por txid).
CREATE FUNCTION soc.purge_publication(p_keep interval DEFAULT interval '7 days')
RETURNS bigint
LANGUAGE sql
SET search_path = pg_catalog, soc
AS $$
    WITH del AS (
        DELETE FROM soc.publication
        WHERE created_at < now() - p_keep
        RETURNING 1
    )
    SELECT count(*) FROM del;
$$;
REVOKE ALL ON FUNCTION soc.purge_publication(interval) FROM PUBLIC;

-- Situação da coleta ----------------------------------------------------------

CREATE VIEW soc.v_collector_status AS
SELECT DISTINCT ON (r.source)
       r.source,
       r.status,
       r.started_at,
       r.finished_at,
       r.fetched,
       r.inserted,
       r.changed,
       r.throttled,
       r.error,
       c.watermark,
       now() - c.watermark AS lag
FROM soc.collector_run r
LEFT JOIN soc.collector_checkpoint c ON c.source = r.source
ORDER BY r.source, r.started_at DESC;

-- Privilégios -----------------------------------------------------------------

GRANT SELECT, INSERT, UPDATE ON soc.collector_checkpoint TO soc_collector;
GRANT SELECT, INSERT, UPDATE ON soc.collector_run        TO soc_collector;
GRANT SELECT, INSERT         ON soc.raw_event            TO soc_collector;
GRANT SELECT, INSERT, UPDATE ON soc.security_object      TO soc_collector;
GRANT SELECT, INSERT         ON soc.security_object_version TO soc_collector;
GRANT INSERT                 ON soc.publication          TO soc_collector;
GRANT SELECT                 ON soc.v_collector_status   TO soc_collector;
GRANT EXECUTE ON FUNCTION soc.ensure_raw_event_partitions(timestamptz, timestamptz) TO soc_collector;

GRANT SELECT ON soc.publication TO soc_logstash;
