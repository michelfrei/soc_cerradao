-- Cenários SINTÉTICOS para o painel "SOC - Acessos aos servidores" (laboratório; nunca em produção).
-- Cada bloco aciona um ponto de atenção. Horários relativos a "agora" (últimas 24 h).
-- Uso: psql -d soc -v ON_ERROR_STOP=1 -f scripts/lab/cenarios-acessos.sql   (como postgres)

SELECT soc.ensure_raw_event_partitions(now() - interval '2 days', now() + interval '1 day');

WITH cenario(account, domain, host, action, logon_type, ip, reason, admin, minutes_ago, seq) AS (
    -- IP público: RDP com sucesso e falhas de rede vindas da internet
    SELECT 'carlos.lima', 'CERRADAO', 'srv-app01', 'LogonSuccess', 'RemoteInteractive', '203.0.113.10', NULL, false, 180, 1
    UNION ALL SELECT 'adm.maria', 'CERRADAO', 'srv-app02', 'LogonFailed', 'Network', '198.51.100.7', 'InvalidUserNameOrPassword', false, 170, 2
    -- Password spraying: uma origem falhando em 8 contas diferentes
    UNION ALL SELECT (ARRAY['ana.souza','jose.silva','maria.santos','pedro.alves','lucas.rocha','julia.melo','rafael.dias','bruna.costa'])[g],
                     'CERRADAO', 'srv-db01', 'LogonFailed', 'Network', '172.16.159.187', 'InvalidUserNameOrPassword', false, 120 - g, 10 + g
           FROM generate_series(1, 8) g
    -- Senha em texto claro (IIS Basic/LDAP simples), com sucesso
    UNION ALL SELECT 'svc.portal', 'CERRADAO', 'srv-file01', 'LogonSuccess', 'NetworkCleartext', '10.10.5.20', NULL, false, 300 - g * 10, 30 + g
           FROM generate_series(1, 6) g
    -- Conta genérica com privilégio local em RDP/console
    UNION ALL SELECT 'Administrador', 'CERRADAO', h, 'LogonSuccess', 'RemoteInteractive', '10.10.2.44', NULL, true, 400 - g * 20, 50 + g
           FROM generate_series(1, 4) g, unnest(ARRAY['srv-app03','fisico-hv01']) h
    UNION ALL SELECT 'convidado', 'CERRADAO', 'srv-db02', 'LogonFailed', 'Interactive', NULL, 'InvalidUserNameOrPassword', false, 90, 70
    -- Bloqueio de conta
    UNION ALL SELECT 'wgsilva', 'CERRADAO', 'srv-app02', 'LogonFailed', 'Network', '10.10.3.15', 'AccountLocked', false, 60 - g, 80 + g
           FROM generate_series(1, 5) g
    -- NewCredentials (runas /netonly)
    UNION ALL SELECT 'adm.joao', 'CERRADAO', 'srv-app01', 'LogonSuccess', 'NewCredentials', NULL, NULL, true, 45, 90
    -- Conta local (domínio = nome do servidor) via rede
    UNION ALL SELECT 'suporte_local', 'SRV-DB01', 'srv-db01', 'LogonSuccess', 'Network', '10.10.1.99', NULL, true, 30, 91
), rows AS (
    SELECT md5('lab-acessos-' || seq || '-' || host || '-' || account || '-' || now()::text) AS key,
           -- Os acessos de RDP/console caem às 03h de Brasília (06h UTC) para aparecer como fora do horário.
           -- (06h UTC mais recente que já passou)
           CASE WHEN logon_type IN ('RemoteInteractive', 'Interactive')
                THEN date_trunc('day', now() - interval '6 hours', 'UTC') + interval '6 hours' - (seq % 5) * interval '7 minutes'
                ELSE now() - minutes_ago * interval '1 minute' END AS ts_utc,
           c.*
    FROM cenario c
), payloads AS (
    SELECT key, ts_utc AS ts, jsonb_strip_nulls(jsonb_build_object(
        'Timestamp', to_char(ts_utc AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
        'DeviceId', md5(host), 'DeviceName', host || '.cerradao.local',
        'ActionType', action, 'LogonType', logon_type,
        'AccountName', account, 'AccountDomain', domain,
        'FailureReason', reason, 'RemoteIP', ip, 'RemoteDeviceName', CASE WHEN ip IS NOT NULL THEN 'ws-' || seq END,
        'Protocol', CASE WHEN logon_type = 'Network' THEN 'NTLM' ELSE 'Negotiate' END,
        'IsLocalAdmin', admin, 'ReportId', 800000 + seq
    )) AS payload
    FROM rows
), ins AS (
    INSERT INTO soc.raw_event (event_key, occurred_at, source, table_name, device_id, device_name, action_type, payload)
    SELECT key, ts, 'lab-acessos', 'DeviceLogonEvents', payload->>'DeviceId', payload->>'DeviceName', payload->>'ActionType', payload
    FROM payloads
    RETURNING event_key, occurred_at, payload
)
INSERT INTO soc.publication (entity, dataset, doc_id, occurred_at, payload)
SELECT 'event', 'devicelogonevents', event_key, occurred_at, payload FROM ins;
