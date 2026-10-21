# Correção: eventos ASR gravados como DeviceLogonEvents (21/10/2026)

**Causa.** `collector/queries/devicelogonevents.kql` estava com a consulta de ASR
(`DeviceEvents | where ActionType startswith "Asr"`). A fonte
`hunting.devicelogonevents` gravou eventos ASR com `table_name = 'DeviceLogonEvents'`,
que foram indexados em `soc-events-devicelogonevents-*`. Os logons reais das janelas
já percorridas não foram coletados.

**Prevenção.** A partir desta versão o coletor recusa iniciar quando a consulta
lê uma tabela diferente da declarada em `sources.json`.

Execute na ordem. Tempo estimado: 10 minutos. Não afeta incidentes, alertas nem `hunting.asr`.

## 1. VM do Docker — parar o coletor e atualizar os arquivos

```bash
cd /home/administrator/soc_cerradao
docker compose -f docker/compose.yml stop collector
git pull            # ou edite collector/queries/devicelogonevents.kql manualmente
head -6 collector/queries/devicelogonevents.kql
```

A consulta deve começar por `DeviceLogonEvents`, não por `DeviceEvents`.

## 2. VM do PostgreSQL — remover os eventos trocados e reiniciar o checkpoint

Primeiro, só a contagem (nada é apagado):

```bash
sudo -u postgres psql -d soc -c "
SELECT count(*) AS asr_como_logon
FROM soc.raw_event
WHERE table_name = 'DeviceLogonEvents' AND action_type LIKE 'Asr%';"
```

Depois, a limpeza em uma única transação:

```bash
sudo -u postgres psql -d soc -v ON_ERROR_STOP=1 <<'SQL'
BEGIN;
DELETE FROM soc.publication
 WHERE entity = 'event' AND dataset = 'devicelogonevents'
   AND payload->>'ActionType' LIKE 'Asr%';
DELETE FROM soc.raw_event
 WHERE table_name = 'DeviceLogonEvents' AND action_type LIKE 'Asr%';
-- Sem checkpoint, a fonte recoleta as últimas 24 h (initialLookbackHours).
DELETE FROM soc.collector_checkpoint WHERE source = 'hunting.devicelogonevents';
COMMIT;
SQL
```

O primeiro `DELETE` mostra quantas publicações removeu e o segundo, quantos eventos;
o segundo deve coincidir com a contagem anterior.

> O Advanced Hunting retém 30 dias. Para recoletar mais que 24 h, em vez de apagar
> o checkpoint, defina a data inicial:
> `UPDATE soc.collector_checkpoint SET watermark = '2026-10-14T00:00:00Z' WHERE source = 'hunting.devicelogonevents';`

## 3. VM do Docker — remover os documentos do Elasticsearch

Contagem:

```bash
cd /home/administrator/soc_cerradao/docker
docker compose exec es01 sh -c 'curl -s --cacert config/certs/ca/ca.crt -u "elastic:$ELASTIC_PASSWORD" \
  "https://localhost:9200/soc-events-devicelogonevents-*/_count" -H "Content-Type: application/json" \
  -d "{\"query\":{\"prefix\":{\"event.action\":\"Asr\"}}}"'
```

Remoção:

```bash
docker compose exec es01 sh -c 'curl -s --cacert config/certs/ca/ca.crt -u "elastic:$ELASTIC_PASSWORD" \
  -X POST "https://localhost:9200/soc-events-devicelogonevents-*/_delete_by_query?refresh=true" \
  -H "Content-Type: application/json" \
  -d "{\"query\":{\"prefix\":{\"event.action\":\"Asr\"}}}"'
```

O campo `deleted` da resposta deve igualar a contagem anterior.

## 4. VM do Docker — reconstruir e iniciar o coletor

A validação nova está no código; por isso é necessário `--build`:

```bash
docker compose up -d --build --no-deps collector
docker compose logs -f collector
```

Esperado: `coleta concluída` para `hunting.devicelogonevents` com `inserted` > 0.
Se aparecer `a consulta lê "DeviceEvents", mas a fonte ... declara a tabela "DeviceLogonEvents"`,
o arquivo `.kql` da VM ainda está errado (passo 1).

## 5. Conferência

```bash
# VM do PostgreSQL
sudo -u postgres psql -d soc -c "
SELECT table_name, left(action_type, 20) AS acao, count(*)
FROM soc.raw_event GROUP BY 1, 2 ORDER BY 1, 3 DESC;"
```

- `DeviceLogonEvents`: somente `LogonSuccess`, `LogonFailed` e similares.
- `DeviceEvents`: somente ações `Asr...`.

No Kibana (Discover, data view `soc-events-*`):
`event.dataset : "defender.devicelogonevents" and event.action : Asr*` deve retornar zero.
