-- 005: inventário TVM de software (fim de suporte) e insights de remediação
-- derivados da postura atual. Aditiva; aplicada como soc_owner.
ALTER TABLE soc.publication DROP CONSTRAINT publication_entity_check;
ALTER TABLE soc.publication ADD CONSTRAINT publication_entity_check
  CHECK (entity IN ('event', 'incident', 'incident_version', 'alert', 'alert_version', 'device', 'posture', 'insight'));

ALTER TABLE soc.posture_state DROP CONSTRAINT posture_state_dataset_check;
ALTER TABLE soc.posture_state ADD CONSTRAINT posture_state_dataset_check
  CHECK (dataset IN ('devicetvmsoftwarevulnerabilities', 'devicetvmsecureconfigurationassessment', 'devicetvmsoftwareinventory'));

-- Um registro por ação de remediação (insight_id estável). Quando nenhum achado
-- ativo sustenta mais a ação, o status vira no_longer_reported: não equivale a
-- correção comprovada. O payload é o documento publicado em soc-insights.
CREATE TABLE soc.remediation_insight (
    insight_id   text PRIMARY KEY,
    status       text NOT NULL CHECK (status IN ('open', 'no_longer_reported')),
    first_seen   timestamptz NOT NULL,
    last_seen    timestamptz NOT NULL,
    generated_at timestamptz NOT NULL,
    content_hash text NOT NULL,
    payload      jsonb NOT NULL
);
GRANT SELECT, INSERT, UPDATE ON soc.remediation_insight TO soc_collector;

-- Reconstrói soc-insights a partir do estado atual. Chamada administrativa.
CREATE FUNCTION soc.republish_insights()
RETURNS bigint LANGUAGE sql SET search_path=pg_catalog,soc AS $$
  WITH publication AS (
    INSERT INTO soc.publication (entity, dataset, doc_id, occurred_at, payload)
    SELECT 'insight', 'remediation', insight_id, generated_at, payload
    FROM soc.remediation_insight
    RETURNING 1
  ) SELECT count(*) FROM publication;
$$;
REVOKE ALL ON FUNCTION soc.republish_insights() FROM PUBLIC;
