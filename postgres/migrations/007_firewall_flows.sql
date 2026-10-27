-- 007: agregados por hora do tráfego da firewall (FortiGate via FortiAnalyzer),
-- calculados pelo coletor a partir de fw-logs-fortigate no Elasticsearch, e sua
-- publicação em soc-fw-flows-*. Aditiva; aplicada como soc_owner.
ALTER TABLE soc.publication DROP CONSTRAINT publication_entity_check;
ALTER TABLE soc.publication ADD CONSTRAINT publication_entity_check
  CHECK (entity IN ('event', 'incident', 'incident_version', 'alert', 'alert_version', 'device', 'posture', 'insight', 'winupdate', 'fwflow'));

-- kind source: hora × IP de origem × direção × veredito (todo o tráfego).
-- kind server: hora × origem × destino × porta × protocolo × veredito, quando origem
-- ou destino está nas redes de servidores configuradas na fonte fwflows.
-- Recalculada por hora inteira (apaga e grava a hora); só o que mudou (content_hash)
-- é republicado. Retenção na própria fonte (retentionDays).
CREATE TABLE soc.fw_flow_hourly (
    hour             timestamptz NOT NULL,
    kind             text NOT NULL CHECK (kind IN ('source', 'server')),
    flow_id          text NOT NULL,
    source_ip        inet NOT NULL,
    destination_ip   inet,
    destination_port integer,
    transport        text,
    direction        text NOT NULL,
    verdict          text NOT NULL CHECK (verdict IN ('allowed', 'blocked')),
    sessions         bigint NOT NULL,
    bytes_sent       bigint NOT NULL,
    bytes_received   bigint NOT NULL,
    destinations     integer,
    users            text[] NOT NULL DEFAULT '{}',
    categories       text[] NOT NULL DEFAULT '{}',
    rules            text[] NOT NULL DEFAULT '{}',
    content_hash     text NOT NULL,
    computed_at      timestamptz NOT NULL,
    PRIMARY KEY (hour, kind, flow_id)
);
CREATE INDEX fw_flow_hourly_source_idx ON soc.fw_flow_hourly (source_ip, hour);
CREATE INDEX fw_flow_hourly_destination_idx ON soc.fw_flow_hourly (destination_ip, hour) WHERE destination_ip IS NOT NULL;
GRANT SELECT, INSERT, DELETE ON soc.fw_flow_hourly TO soc_collector;
