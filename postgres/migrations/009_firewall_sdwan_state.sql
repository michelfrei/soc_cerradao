-- 009: estado dos links SD-WAN (up/down por interface e health-check) na mesma tabela
-- de estado das sessões da firewall. Aditiva; aplicada como soc_owner.
ALTER TABLE soc.fw_session_state DROP CONSTRAINT fw_session_state_state_check;
ALTER TABLE soc.fw_session_state ADD CONSTRAINT fw_session_state_state_check
  CHECK (state IN ('open', 'closed', 'stale', 'unknown', 'up', 'down'));
