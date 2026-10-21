-- Dados SINTÉTICOS para laboratório (nunca rode no banco de produção).
-- Gera 7 dias de logons, eventos ASR, incidentes e alertas fictícios, gravados
-- como o coletor grava (raw_event/security_object + publication), para testar
-- o Logstash, os dashboards e as regras de detecção.
-- Uso: psql -d soc -v ON_ERROR_STOP=1 -f scripts/lab/dados-sinteticos.sql   (como postgres)

SELECT soc.ensure_raw_event_partitions(now() - interval '8 days', now() + interval '1 day');

-- Logons -------------------------------------------------------------------------
WITH servers AS (
    SELECT unnest(ARRAY['srv-app01','srv-app02','srv-app03','srv-db01','srv-db02','srv-file01','fisico-hv01']) AS host
), base AS (
    SELECT
        g AS n,
        now() - interval '7 days' + (g * interval '2 minutes') + (random() * interval '90 seconds') AS ts,
        (ARRAY['srv-app01','srv-app02','srv-app03','srv-db01','srv-db02','srv-file01','fisico-hv01'])[1 + (g % 7)] AS host,
        CASE
            WHEN g % 11 = 0 THEN 'adm.joao'
            WHEN g % 13 = 0 THEN 'adm.maria'
            WHEN g % 5 = 0 THEN 'svc.backup'
            WHEN g % 7 = 0 THEN 'svc.sql'
            WHEN g % 3 = 0 THEN 'SRV-APP01$'
            ELSE (ARRAY['jose.silva','ana.souza','carlos.lima','maria.santos'])[1 + (g % 4)]
        END AS account,
        g % 17 AS r
    FROM generate_series(1, 5000) g
), rows AS (
    SELECT
        md5('lab-logon-' || n) AS key,
        ts,
        jsonb_build_object(
            'Timestamp', to_char(ts AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
            'DeviceId', md5(host),
            'DeviceName', host || '.cerradao.local',
            'ActionType', CASE WHEN r IN (3, 9) THEN 'LogonFailed' WHEN r = 15 THEN 'LogonSuccessAggregatedReport' ELSE 'LogonSuccess' END,
            'LogonType', CASE
                WHEN account LIKE 'svc.%' THEN (ARRAY['Service','Batch','Network'])[1 + (n % 3)]
                WHEN account LIKE 'adm.%' AND n % 2 = 0 THEN 'RemoteInteractive'
                WHEN account LIKE '%$' THEN 'Network'
                ELSE (ARRAY['Network','Network','RemoteInteractive','Interactive'])[1 + (n % 4)]
            END,
            'AccountName', account,
            'AccountDomain', 'CERRADAO',
            'AccountSid', 'S-1-5-21-1000-' || abs(hashtext(account)),
            'Protocol', (ARRAY['Kerberos','NTLM','Negotiate'])[1 + (n % 3)],
            'FailureReason', CASE WHEN r IN (3, 9) THEN (ARRAY['InvalidUserNameOrPassword','AccountLocked'])[1 + (n % 2)] END,
            'RemoteIP', '10.10.' || (n % 4) || '.' || (10 + n % 40),
            'RemoteDeviceName', 'ws-' || (n % 40),
            'RemotePort', 49152 + (n % 10000),
            'IsLocalAdmin', (account LIKE 'adm.%')::text,
            'LogonId', (100000 + n)::text,
            'ReportId', n,
            'InitiatingProcessFileName', 'lsass.exe'
        ) AS payload
    FROM base
), ins AS (
    INSERT INTO soc.raw_event (event_key, occurred_at, source, table_name, device_id, device_name, action_type, payload)
    SELECT key, ts, 'lab', 'DeviceLogonEvents', payload->>'DeviceId', payload->>'DeviceName', payload->>'ActionType', payload
    FROM rows
    ON CONFLICT DO NOTHING
    RETURNING event_key, occurred_at, payload
)
INSERT INTO soc.publication (entity, dataset, doc_id, occurred_at, payload)
SELECT 'event', 'devicelogonevents', event_key, occurred_at, payload FROM ins;

-- ASR -------------------------------------------------------------------------------
WITH base AS (
    SELECT
        g AS n,
        now() - interval '7 days' + (g * interval '25 minutes') AS ts,
        (ARRAY['srv-app01','srv-app02','srv-db01','srv-file01','fisico-hv01'])[1 + (g % 5)] AS host,
        (ARRAY['AsrLsassCredentialTheftAudited','AsrLsassCredentialTheftAudited','AsrAbusedSystemToolBlocked',
               'AsrAbusedSystemToolAudited','AsrPsexecWmiChildProcessAudited','AsrOfficeChildProcessBlocked'])[1 + (g % 6)] AS action
    FROM generate_series(1, 400) g
), rows AS (
    SELECT md5('lab-asr-' || n) AS key, ts,
        jsonb_build_object(
            'Timestamp', to_char(ts AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
            'DeviceId', md5(host), 'DeviceName', host || '.cerradao.local',
            'ActionType', action,
            'FileName', (ARRAY['lsass.exe','certutil.exe','wmiprvse.exe','powershell.exe'])[1 + (n % 4)],
            'FolderPath', 'C:\Windows\System32',
            'InitiatingProcessFileName', (ARRAY['taskmgr.exe','cmd.exe','winword.exe','backupagent.exe'])[1 + (n % 4)],
            'InitiatingProcessAccountName', (ARRAY['svc.backup','adm.joao','jose.silva'])[1 + (n % 3)],
            'ReportId', n
        ) AS payload
    FROM base
), ins AS (
    INSERT INTO soc.raw_event (event_key, occurred_at, source, table_name, device_id, device_name, action_type, payload)
    SELECT key, ts, 'lab', 'DeviceEvents', payload->>'DeviceId', payload->>'DeviceName', payload->>'ActionType', payload
    FROM rows
    ON CONFLICT DO NOTHING
    RETURNING event_key, occurred_at, payload
)
INSERT INTO soc.publication (entity, dataset, doc_id, occurred_at, payload)
SELECT 'event', 'deviceevents', event_key, occurred_at, payload FROM ins;

-- Incidentes e alertas ---------------------------------------------------------------
WITH inc AS (
    SELECT g,
        jsonb_build_object(
            'id', (1000 + g)::text,
            'displayName', (ARRAY['Atividade suspeita de PowerShell','Movimentação lateral suspeita',
                                  'Tentativa de roubo de credenciais','Execução de ferramenta de administração remota',
                                  'Logon RDP incomum'])[1 + (g % 5)] || ' em srv-app0' || (1 + g % 3),
            'status', (ARRAY['active','active','inProgress','resolved'])[1 + (g % 4)],
            'severity', (ARRAY['high','medium','low','medium','informational'])[1 + (g % 5)],
            'assignedTo', CASE WHEN g % 3 = 0 THEN 'analista@cerradao.com.br' END,
            'classification', 'unknown',
            'determination', 'unknown',
            'createdDateTime', to_char((now() - g * interval '9 hours') AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
            'lastUpdateDateTime', to_char((now() - g * interval '7 hours') AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
            'incidentWebUrl', 'https://security.microsoft.com/incidents/' || (1000 + g)
        ) AS p
    FROM generate_series(1, 18) g
), al AS (
    SELECT g,
        jsonb_build_object(
            'id', 'da' || md5('lab-alert-' || g),
            'title', (ARRAY['Suspicious PowerShell command line','Possible lateral movement','Credential theft attempt',
                            'Suspicious RDP session','ASR rule blocked suspicious activity'])[1 + (g % 5)],
            'status', (ARRAY['new','inProgress','resolved','new'])[1 + (g % 4)],
            'severity', (ARRAY['high','medium','low','medium'])[1 + (g % 4)],
            'serviceSource', (ARRAY['microsoftDefenderForEndpoint','microsoftDefenderForEndpoint','microsoftDefenderForIdentity','microsoftDefenderForOffice365'])[1 + (g % 4)],
            'incidentId', (1000 + 1 + g % 18)::text,
            'createdDateTime', to_char((now() - g * interval '3 hours') AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
            'lastUpdateDateTime', to_char((now() - g * interval '2 hours') AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
            'alertWebUrl', 'https://security.microsoft.com/alerts/da' || g
        ) AS p
    FROM generate_series(1, 60) g
), objs AS (
    SELECT 'incident' AS kind, p FROM inc UNION ALL SELECT 'alert', p FROM al
), up AS (
    INSERT INTO soc.security_object (kind, id, title, status, severity, assigned_to, service_source, incident_id,
                                     web_url, created_at, last_update_at, payload_hash, payload)
    SELECT kind, p->>'id', coalesce(p->>'displayName', p->>'title'), p->>'status', p->>'severity', p->>'assignedTo',
           p->>'serviceSource', coalesce(p->>'incidentId', p->>'id'), coalesce(p->>'incidentWebUrl', p->>'alertWebUrl'),
           (p->>'createdDateTime')::timestamptz, (p->>'lastUpdateDateTime')::timestamptz, md5(p::text), p
    FROM objs
    ON CONFLICT DO NOTHING
    RETURNING kind, id, payload_hash, last_update_at, payload
), ver AS (
    INSERT INTO soc.security_object_version (kind, id, payload_hash, last_update_at, payload)
    SELECT kind, id, payload_hash, last_update_at, payload FROM up
)
INSERT INTO soc.publication (entity, dataset, doc_id, occurred_at, payload)
SELECT kind, kind, id, last_update_at, payload FROM up
UNION ALL
SELECT kind || '_version', kind, id || ':' || payload_hash, last_update_at, payload FROM up;
