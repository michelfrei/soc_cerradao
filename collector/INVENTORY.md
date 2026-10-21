# Inventário conhecido e esperado

`inventory.deviceinfo` consulta `DeviceInfo` a cada hora: última observação por
DeviceId nos últimos 30 dias. Nomes incluem `srv` ou `fisico` e excluem `note` ou
`micro`, sem diferenciar caixa; exclusões prevalecem. O mesmo filtro está nas
consultas de logon e ASR. Incidentes/alertas globais não recebem esse filtro.

O snapshot é recusado se atingir 10000 linhas (ou `maxRows`, se menor). O coletor
não publica um snapshot que possa ter sido truncado. O limite inclui os dados
retornados pela API antes de qualquer tratamento local.

## Ativos esperados opcionais

`config/assets.json` começa com `{"assets":[]}`. Cada item exige `name`; `id`
(DeviceId) é opcional, assim como `owner`, `environment`, `criticality`, todos strings. Exemplo:

```json
{"assets":[{"name":"srv-app01.exemplo.local","owner":"Infra","environment":"prod","criticality":"high"}]}
```

O arquivo é carregado ao iniciar o coletor, ao lado de `sources.json`; `ASSETS_FILE`
pode definir outro caminho. Arquivo ausente significa lista vazia. JSON inválido
ou sem acesso falha explicitamente. A lista não restringe quais logs são coletados.
Expectativas por nome devem respeitar o filtro de servidores; nomes ambíguos
exigem DeviceId. Correspondência de nomes é exata, ignorando caixa e espaços nas
pontas; não remove domínio/FQDN, para evitar unir máquinas diferentes.

Um ativo novo observado recebe chave DeviceId. Um esperado ainda não observado
recebe `expected:<nome normalizado>` (ou seu DeviceId explícito). Quando é reconhecido,
conserva essa chave, evitando dois documentos no Elasticsearch. Adicionar uma
expectativa a um observado também reutiliza a chave existente. IDs diferentes com
o mesmo nome permanecem ativos diferentes. `SOCCatalogName` conserva o nome do
catálogo esperado e permite manter o vínculo após renomear o dispositivo no Defender,
mesmo quando ele já era observado antes de entrar no catálogo. DeviceId explícito
continua sendo a identidade preferencial e resolve nomes ambíguos. A expectativa
sempre precisa de nome para que um ativo ainda não observado apareça no escopo.

## Contrato de publicação

Estado atual: `soc.device_inventory`; entidade `device`, dataset `deviceinfo`,
doc_id = chave persistente. `occurred_at` é o horário do snapshot. Payload mantém
`DeviceId`, `DeviceName`, `Timestamp`, `OSPlatform`, `DeviceType`, `MachineGroup`,
`OnboardingStatus`, `SensorHealthState` e acrescenta `SOCExpected`, `SOCObserved`,
`SOCOwner`, `SOCEnvironment`, `SOCCriticality`, `SOCSnapshotAt`, `SOCCatalogName`.

`Timestamp` é a observação original do Defender, preservada no JSON sem truncar
frações. `SOCSnapshotAt` indica quando o coletor recebeu a visão. `SOCObserved`
significa presença no snapshot atual de 30 dias, **não** sensor online neste momento.
Silenciosos não são apagados: mantêm último payload/horário, com `SOCObserved=false`.
Alterar a lista esperada atualiza metadados no próximo ciclo; removidos da lista
ficam conhecidos, porém `SOCExpected=false`. Não há exclusão automática de ativos.

Inventário do Defender não descobre máquinas nunca onboarded. Lista esperada vazia
é denominador desconhecido, não cobertura de 100%. Percentuais de cobertura exigem
lista esperada e comparação explícita entre esperado e observado. Saúde do sensor e
idade da última observação precisam ser analisadas separadamente.

## Telemetria PostgreSQL

`soc.v_telemetry` pertence a `soc_owner`, com SELECT para `soc_logstash`; não expõe
payloads nem concede leitura de tabelas brutas. `logstash/sql/telemetry.sql` lê um
snapshot independente do cursor de publicação, com IDs estáveis por fonte/minuto.

`collector_status` usa o último run **concluído** por fonte e inclui source/status,
lag_seconds (NULL sem checkpoint), duration_ms, fetched/inserted/changed/api_calls/
throttled, finished_at e horários de janela/checkpoint. Um run em andamento não
esconde o último resultado. Ausência de run concluído não produz métrica dessa fonte.

`database_capacity` inclui source=`database.capacity`, database_bytes (banco todo),
raw_bytes (soma de `pg_total_relation_size` das partições folha), publication_bytes
e history_bytes (`security_object_version`, incluindo índices/TOAST). Não varre
eventos para medir tamanho. Essas medidas são ocupação atual, não tamanho livre do
volume, previsão de esgotamento ou prova de capacidade do servidor.
