-- 004: snapshots completos de postura TVM, mantendo estados desaparecidos como
-- no_longer_reported (não equivale a corrigido). Aplicada como soc_owner.
ALTER TABLE soc.publication DROP CONSTRAINT publication_entity_check;
ALTER TABLE soc.publication ADD CONSTRAINT publication_entity_check
  CHECK (entity IN ('event', 'incident', 'incident_version', 'alert', 'alert_version', 'device', 'posture'));

CREATE TABLE soc.posture_state (
    dataset     text NOT NULL CHECK (dataset IN ('devicetvmsoftwarevulnerabilities', 'devicetvmsecureconfigurationassessment')),
    doc_id      text NOT NULL,
    device_id   text NOT NULL,
    active      boolean NOT NULL,
    snapshot_at timestamptz NOT NULL,
    payload     jsonb NOT NULL,
    first_seen_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (dataset, doc_id)
);
CREATE INDEX posture_state_device_idx ON soc.posture_state (device_id, dataset);
GRANT SELECT, INSERT, UPDATE ON soc.posture_state TO soc_collector;

-- Reconstrói o índice atual preservando inclusive tombstones; Logstash continua
-- com SELECT apenas na publicação. A chamada é administrativa, não do coletor.
CREATE FUNCTION soc.republish_posture(p_dataset text)
RETURNS bigint LANGUAGE sql SET search_path=pg_catalog,soc AS $$
  WITH publication AS (
    INSERT INTO soc.publication (entity, dataset, doc_id, occurred_at, payload)
    SELECT 'posture', dataset, doc_id, snapshot_at, payload
    FROM soc.posture_state WHERE dataset=p_dataset
    RETURNING 1
  ) SELECT count(*) FROM publication;
$$;
REVOKE ALL ON FUNCTION soc.republish_posture(text) FROM PUBLIC;
