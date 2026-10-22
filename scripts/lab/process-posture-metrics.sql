-- Somente laboratório descartável. Falha recente precisa continuar visível,
-- conservando o checkpoint antigo. Vazio bem-sucedido é outro estado.
INSERT INTO soc.collector_checkpoint(source,watermark)
VALUES ('snapshot.devicetvmsoftwarevulnerabilities',now()-interval '8 hours'),
       ('snapshot.devicetvmsecureconfigurationassessment',now()-interval '1 minute');

INSERT INTO soc.collector_run(source,status,started_at,finished_at,fetched,api_calls,error)
VALUES ('snapshot.devicetvmsoftwarevulnerabilities','success',now()-interval '8 hours 1 minute',now()-interval '8 hours',2,1,NULL),
       ('snapshot.devicetvmsoftwarevulnerabilities','failed',now()-interval '2 minutes',now()-interval '1 minute',0,1,'Falha sintética: não comprova ausência de risco'),
       ('snapshot.devicetvmsecureconfigurationassessment','success',now()-interval '2 minutes',now()-interval '1 minute',0,1,NULL),
       ('hunting.deviceprocessevents','success',now()-interval '2 minutes',now()-interval '1 minute',2,1,NULL),
       ('hunting.devicenetworkevents','success',now()-interval '2 minutes',now()-interval '1 minute',2,1,NULL);
