-- Independente de sql_last_value: um snapshot a cada minuto, IDs estáveis por fonte/minuto.
-- v_telemetry pertence a soc_owner e expõe somente métricas agregadas.
SELECT id, txid, entity, dataset, doc_id, occurred_at_iso, payload_json
FROM soc.v_telemetry
ORDER BY dataset, doc_id
