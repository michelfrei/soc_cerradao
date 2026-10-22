-- Dados fictícios: execução apenas no banco descartável de smoke-evolution.mjs.
INSERT INTO soc.publication(entity,dataset,doc_id,occurred_at,payload)
SELECT 'event','deviceprocessevents','smoke-process-' || n,now(),
  jsonb_build_object('Timestamp',now(),'DeviceId','process-host-' || n,'DeviceName',hostname,
    'ActionType','ProcessCreated','FileName','powershell.exe','FolderPath','C:\Windows\System32\WindowsPowerShell\v1.0',
    'ProcessCommandLine','powershell.exe -NoProfile -File C:\Lab\test.ps1',
    'ProcessId',4200,'ProcessCreationTime',now(),'ProcessUniqueId','created-4200',
    'AccountName','operator','AccountDomain','lab','AccountSid','S-1-5-21-111-222-333-1001',
    'SHA1',repeat('a',40),'SHA256',repeat('b',64),
    'InitiatingProcessFileName','cmd.exe','InitiatingProcessId',4100,
    'InitiatingProcessUniqueId','parent-4100','InitiatingProcessCommandLine','cmd.exe /c test',
    'InitiatingProcessAccountName','parent-account','InitiatingProcessAccountDomain','lab')
FROM (VALUES (1,'srv-process-test'),(2,'FISICO-process-test'),
             (3,'srv-note-excluded'),(4,'fisico-micro-excluded')) AS f(n,hostname);

INSERT INTO soc.publication(entity,dataset,doc_id,occurred_at,payload)
SELECT 'event','devicenetworkevents','smoke-network-' || n,now(),
  jsonb_build_object('Timestamp',now(),'DeviceId','network-host-' || n,'DeviceName',hostname,
    'ActionType','ConnectionSuccess','LocalIP','10.20.30.40','LocalPort',53421,
    'RemoteIP','203.0.113.8','RemotePort',443,'RemoteUrl','example.test',
    'LocalIPType','Private','RemoteIPType','Public','Protocol','Tcp',
    'InitiatingProcessFileName','powershell.exe','InitiatingProcessId',4200,
    'InitiatingProcessUniqueId','created-4200','InitiatingProcessCommandLine','powershell.exe -NoProfile',
    'InitiatingProcessAccountName','network-account','InitiatingProcessAccountDomain','lab')
FROM (VALUES (1,'srv-network-test'),(2,'fisico-network-test'),
             (3,'srv-note-excluded'),(4,'fisico-micro-excluded')) AS f(n,hostname);

INSERT INTO soc.publication(entity,dataset,doc_id,occurred_at,payload)
SELECT 'posture','devicetvmsoftwarevulnerabilities','smoke-vuln-' || n,now(),
  jsonb_build_object('DeviceId','posture-host-' || n,'DeviceName',hostname,
    'CveId','CVE-2099-0001','SoftwareVendor','lab','SoftwareName','synthetic-app','SoftwareVersion','1.0',
    'VulnerabilitySeverityLevel','Critical','CvssScore','9.8','IsExploitAvailable',true,
    'SOCActive',true,'SOCState','observed','SOCSnapshotAt',now())
FROM (VALUES (1,'srv-posture-test'),(2,'fisico-posture-test'),
             (3,'srv-note-excluded'),(4,'fisico-micro-excluded')) AS f(n,hostname);

-- Mesmo id: o snapshot novo retira o item. Uma republicação antiga subsequente
-- não pode ressuscitá-lo (external_gte usa SOCSnapshotAt, e não chegada).
INSERT INTO soc.publication(entity,dataset,doc_id,occurred_at,payload)
SELECT 'posture','devicetvmsoftwarevulnerabilities','smoke-vuln-removed',at,
  jsonb_build_object('DeviceId','posture-removed','DeviceName','srv-posture-removed',
    'CveId','CVE-2099-0002','SoftwareName','synthetic-app','SoftwareVersion','0.9',
    'SOCActive',active,'SOCState',state,'SOCSnapshotAt',at)
FROM (VALUES (now()-interval '2 hours',true,'observed'),
             (now()-interval '1 hour',false,'no_longer_reported'),
             (now()-interval '2 hours',true,'observed')) AS f(at,active,state);

INSERT INTO soc.publication(entity,dataset,doc_id,occurred_at,payload)
VALUES ('posture','devicetvmsecureconfigurationassessment','smoke-configuration',now(),
  jsonb_build_object('DeviceId','posture-host-1','DeviceName','srv-posture-test',
    'Timestamp',now(),'ConfigurationId','scid-lab','ConfigurationName','Avaliação sintética de antivírus',
    'ConfigurationCategory','SecurityControls','ConfigurationSubcategory','Antivirus',
    'IsApplicable',true,'IsCompliant',false,'Context',jsonb_build_object('test',true),
    'SOCActive',true,'SOCState','observed','SOCSnapshotAt',now()));

UPDATE soc.publication SET payload=payload ||
  '{"ExposureLevel":"High","AssetValue":"High","IsInternetFacing":true}'::jsonb
WHERE entity='device' AND doc_id='smoke-observed';
