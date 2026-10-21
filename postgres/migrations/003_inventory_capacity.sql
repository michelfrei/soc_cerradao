-- 003: inventário atual e métricas locais para o SOC. Aplicada como soc_owner.
ALTER TABLE soc.publication DROP CONSTRAINT publication_entity_check;
ALTER TABLE soc.publication ADD CONSTRAINT publication_entity_check
  CHECK (entity IN ('event', 'incident', 'incident_version', 'alert', 'alert_version', 'device'));

CREATE TABLE soc.device_inventory (
    inventory_key text PRIMARY KEY,
    device_id     text,
    device_name   text,
    last_seen_at  timestamptz,
    snapshot_at   timestamptz NOT NULL,
    payload       jsonb NOT NULL,
    first_seen_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX device_inventory_device_id_idx ON soc.device_inventory (device_id) WHERE device_id IS NOT NULL;
GRANT SELECT, INSERT, UPDATE ON soc.device_inventory TO soc_collector;

-- Definer view: Logstash não recebe acesso às tabelas de coleta ou eventos.
-- Métricas por minuto são reconsultáveis; documentos do mesmo minuto têm ID estável.
CREATE VIEW soc.v_telemetry WITH (security_invoker = false) AS
WITH sample AS (
    SELECT date_trunc('minute', now()) AS sampled_at
), completed AS (
    SELECT DISTINCT ON (source) *
    FROM soc.collector_run
    WHERE finished_at IS NOT NULL AND status IN ('success', 'failed')
    ORDER BY source, finished_at DESC, id DESC
), metrics AS (
    SELECT 'collector_status'::text AS dataset,
           r.source AS metric_key,
           s.sampled_at,
           jsonb_build_object(
               'source', r.source, 'status', r.status,
               'lag_seconds', CASE WHEN c.watermark IS NULL THEN NULL
                                   ELSE greatest(0, extract(epoch FROM now() - c.watermark)) END,
               'duration_ms', extract(epoch FROM r.finished_at - r.started_at) * 1000,
               'fetched', r.fetched, 'inserted', r.inserted, 'changed', r.changed,
               'api_calls', r.api_calls, 'throttled', r.throttled,
               'finished_at', r.finished_at, 'started_at', r.started_at,
               'watermark', c.watermark, 'window_start', r.window_start, 'window_end', r.window_end
           ) AS payload
    FROM completed r
    LEFT JOIN soc.collector_checkpoint c ON c.source = r.source
    CROSS JOIN sample s
    UNION ALL
    SELECT 'database_capacity', 'database.capacity', s.sampled_at,
           jsonb_build_object(
               'source', 'database.capacity',
               'database_bytes', pg_database_size(current_database()),
               'raw_bytes', coalesce((SELECT sum(pg_total_relation_size(relid))
                                    FROM pg_partition_tree('soc.raw_event'::regclass) WHERE isleaf), 0),
               'publication_bytes', pg_total_relation_size('soc.publication'::regclass),
               'history_bytes', pg_total_relation_size('soc.security_object_version'::regclass)
           )
    FROM sample s
)
SELECT 0::bigint AS id, 0::bigint AS txid, 'metric'::text AS entity, dataset,
       metric_key || ':' || to_char(sampled_at AT TIME ZONE 'UTC', 'YYYYMMDDHH24MI') AS doc_id,
       to_char(sampled_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS occurred_at_iso,
       payload::text AS payload_json
FROM metrics;
ALTER VIEW soc.v_telemetry OWNER TO soc_owner;
REVOKE ALL ON soc.v_telemetry FROM PUBLIC;
GRANT SELECT ON soc.v_telemetry TO soc_logstash;
CREATE INDEX collector_run_completed_idx ON soc.collector_run (source, finished_at DESC, id DESC)
  WHERE finished_at IS NOT NULL AND status IN ('success', 'failed');
