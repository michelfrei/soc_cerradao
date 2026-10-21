-- Somente o laboratório descartável criado por smoke-evolution.mjs.
INSERT INTO soc.publication(entity,dataset,doc_id,occurred_at,payload)
SELECT 'event','devicelogonevents','smoke-' || n, now() - interval '1 minute',
       jsonb_build_object('Timestamp', now() - interval '1 minute', 'DeviceId', 'smoke-host-' || n,
         'DeviceName', hostname, 'AccountName','admin', 'AccountDomain', realm,
         'ActionType','LogonSuccess', 'LogonType','RemoteInteractive', 'RemoteIP','192.0.2.10',
         'AccountSid', CASE WHEN n = 1 THEN 'S-1-5-21-1-2-3-1001' ELSE NULL END)
FROM (VALUES (1,'srv-smoke-a','domain-a'), (2,'fisico-smoke-b','domain-b'),
             (3,'srv-smoke-c','srv-smoke-c'), (4,'srv-smoke-d','srv-smoke-d'),
             (5,'srv-note-excluded','domain-a'), (6,'fisico-micro-excluded','domain-a'))
AS fixture(n,hostname,realm);

INSERT INTO soc.publication(entity,dataset,doc_id,occurred_at,payload)
VALUES ('device','deviceinfo','expected:srv-smoke-missing',now(),
  jsonb_build_object('DeviceName','srv-smoke-missing','SOCExpected',true,'SOCObserved',false,
    'SOCOwner','Laboratório','SOCEnvironment','test','SOCCriticality','high', 'SOCSnapshotAt',now()));

INSERT INTO soc.publication(entity,dataset,doc_id,occurred_at,payload)
VALUES ('device','deviceinfo','smoke-observed',now(),
  jsonb_build_object('DeviceId','smoke-observed','DeviceName','srv-smoke-observed','SOCExpected',true,
    'SOCObserved',true,'Timestamp',now(),'SensorHealthState','Active','OnboardingStatus','Onboarded',
    'DeviceType','Server','OSPlatform','WindowsServer2022','SOCSnapshotAt',now()));

INSERT INTO soc.publication(entity,dataset,doc_id,occurred_at,payload)
VALUES ('incident','incident','smoke-old-active',now() - interval '45 days',
  jsonb_build_object('id','smoke-old-active','displayName','Incidente antigo ainda aberto (teste)',
    'status','active','severity','high','createdDateTime',now() - interval '46 days',
    'lastUpdateDateTime',now() - interval '45 days'));
