-- 008: estado atual das sessões de VPN e de administração do FortiGate, calculado
-- pelo coletor (fonte fwsessions) a partir de fw-logs-fortigate e publicado em
-- soc-fw-sessions. Aditiva; aplicada como soc_owner.
ALTER TABLE soc.publication DROP CONSTRAINT publication_entity_check;
ALTER TABLE soc.publication ADD CONSTRAINT publication_entity_check
  CHECK (entity IN ('event', 'incident', 'incident_version', 'alert', 'alert_version', 'device', 'posture', 'insight', 'winupdate', 'fwflow', 'fwsession'));

-- Uma linha por sessão (soc.fw.session.id: sn do login admin, tunnelid da VPN).
-- open/stale: sem fechamento; closed: encerrada; unknown: saiu da janela consultada
-- sem fechamento. Encerradas e unknown saem após retentionDays.
CREATE TABLE soc.fw_session_state (
    session_id   text PRIMARY KEY,
    kind         text NOT NULL,
    state        text NOT NULL CHECK (state IN ('open', 'closed', 'stale', 'unknown')),
    last_seen    timestamptz NOT NULL,
    content_hash text NOT NULL,
    payload      jsonb NOT NULL,
    updated_at   timestamptz NOT NULL
);
CREATE INDEX fw_session_state_state_idx ON soc.fw_session_state (state, last_seen);
GRANT SELECT, INSERT, UPDATE, DELETE ON soc.fw_session_state TO soc_collector;
