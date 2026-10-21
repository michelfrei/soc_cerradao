-- Cenários SINTÉTICOS de ataque para validar as regras de detecção no laboratório
-- (nunca rode no banco de produção). Gera eventos com horário "agora":
--   teste.lateral : sucesso em 6 servidores distintos em ~10 min  -> soc-conta-muitos-servidores
--   teste.rajada  : 12 falhas no mesmo servidor em ~6 min          -> soc-rajada-falhas-logon
--   teste.bruta   : 6 falhas seguidas de sucesso em ~7 min         -> soc-forca-bruta-sucesso
-- As regras rodam a cada 10 min; os alertas aparecem em Security > Alerts.
-- Uso: psql -d soc -v ON_ERROR_STOP=1 -f scripts/lab/cenarios-deteccao.sql   (como postgres)

SELECT soc.ensure_raw_event_partitions(now() - interval '1 hour', now() + interval '1 hour');

WITH cenario(account, host, action, logon_type, minutes_ago, seq) AS (
    SELECT 'teste.lateral', 'srv-lab0' || g, 'LogonSuccess', 'Network', 12 - g * 2, g FROM generate_series(1, 6) g
    UNION ALL
    SELECT 'teste.rajada', 'srv-db01', 'LogonFailed', 'Network', 8 - g * 0.5, 100 + g FROM generate_series(1, 12) g
    UNION ALL
    SELECT 'teste.bruta', 'srv-app02', 'LogonFailed', 'Network', 9 - g, 200 + g FROM generate_series(1, 6) g
    UNION ALL
    SELECT 'teste.bruta', 'srv-app02', 'LogonSuccess', 'Network', 2, 300
), rows AS (
    SELECT md5('lab-cenario-' || seq || '-' || now()::text) AS key,
           now() - minutes_ago * interval '1 minute' AS ts, account, host, action, logon_type, seq
    FROM cenario
), payloads AS (
    SELECT key, ts, jsonb_build_object(
        'Timestamp', to_char(ts AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
        'DeviceId', md5(host), 'DeviceName', host || '.cerradao.local',
        'ActionType', action, 'LogonType', logon_type,
        'AccountName', account, 'AccountDomain', 'CERRADAO',
        'FailureReason', CASE WHEN action = 'LogonFailed' THEN 'InvalidUserNameOrPassword' END,
        'RemoteIP', '10.99.0.' || (seq % 200), 'Protocol', 'NTLM',
        'ReportId', 900000 + seq
    ) AS payload
    FROM rows
), ins AS (
    INSERT INTO soc.raw_event (event_key, occurred_at, source, table_name, device_id, device_name, action_type, payload)
    SELECT key, ts, 'lab-cenario', 'DeviceLogonEvents', payload->>'DeviceId', payload->>'DeviceName', payload->>'ActionType', payload
    FROM payloads
    RETURNING event_key, occurred_at, payload
)
INSERT INTO soc.publication (entity, dataset, doc_id, occurred_at, payload)
SELECT 'event', 'devicelogonevents', event_key, occurred_at, payload FROM ins;
