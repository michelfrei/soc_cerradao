# Decisões técnicas

Registro curto das decisões que afetam a correção dos dados. Atualize ao mudar qualquer uma.

## D1 — Publicação incremental por `xid8` (PostgreSQL → Logstash)

**Problema.** O Logstash JDBC lembra o último valor lido (`sql_last_value`). Com
`id` sequencial ou `created_at`, uma transação que obteve um id menor e confirmou
depois de outra seria pulada.

**Decisão.** `soc.publication.txid xid8 DEFAULT pg_current_xact_id()` e a consulta:

```sql
WHERE txid > :sql_last_value
  AND txid < pg_snapshot_xmin(pg_current_snapshot())
ORDER BY txid, id
```

Toda transação com xid abaixo do `xmin` do snapshot já terminou, e as linhas de
uma transação ficam visíveis juntas. Logo, o `>` estrito não perde registros.
Coberto por `test/db.integration.test.ts` ("não avança sobre transação ainda aberta").

**Consequências.**
- Não habilitar `jdbc_paging_enabled` (quebraria a leitura atômica por transação).
- Uma transação longa em qualquer sessão atrasa a publicação. Mitigação:
  `idle_in_transaction_session_timeout` global (15 min) e por papel (2 min).
- O `sql_last_value` avança quando a consulta termina, não quando o Elasticsearch
  confirma. A fila persistente do Logstash cobre reinícios; para perda do volume
  do Logstash, use `soc.republish_events`.

## D2 — Identificadores determinísticos

| Dado | Chave |
|---|---|
| Evento de hunting | `sha256(tabela, DeviceId, ReportId, Timestamp, ActionType)`; sem esses campos, hash da linha |
| Incidente/alerta (estado atual) | `id` do Graph |
| Versão de incidente/alerta | `id:sha256(payload canônico)` |

Reindexar o mesmo período sobrescreve os mesmos documentos. A unicidade de
`ReportId` por dispositivo deve ser confirmada com os dados reais do piloto.

## D3 — Estado atual protegido contra ordem invertida

- No PostgreSQL, o upsert só altera o estado se o hash mudou **e** o
  `lastUpdateDateTime` recebido não é anterior ao gravado.
- No Elasticsearch, `soc-incidents` e `soc-alerts` usam `version_type: external_gte`
  com o `lastUpdateDateTime` em milissegundos. Versões antigas são recusadas (409)
  e aparecem no log do Logstash como conflito, o que é esperado.

## D4 — Índices do Elasticsearch

- Eventos: `soc-events-<tabela>-AAAA.MM` pela data do evento, sem rollover, para que
  reindexar o mesmo `_id` caia sempre no mesmo índice.
- Retenção por ILM: eventos ~90 dias pesquisáveis (exclusão 120 dias após a criação
  do índice mensal); histórico ~12 meses.
- Mapeamento `dynamic: false` com campos ECS explícitos. O registro original fica em
  `defender` (tipo `flattened`), consultável sem explosão de mapeamento.
- Réplicas 0 enquanto houver um único nó.

## D5 — Checkpoint na mesma transação dos dados

- Hunting: cada janela grava eventos, publicação e checkpoint numa transação.
  Quando a resposta atinge `maxRows`, a janela é dividida ao meio e cada parte é
  gravada assim que chega (memória limitada a uma resposta). O checkpoint vai na
  transação da última parte, portanto só avança depois de todas gravadas.
- Reconciliação: fontes `reconcile.*` percorrem as mesmas consultas com 24 h de
  atraso, em janelas de 1 h, recuperando eventos que chegam tarde ao Defender.
- Incidentes/alertas: cada página em sua transação; o checkpoint avança somente
  na transação da última página. Uma falha no meio repete a coleta inteira, sem
  duplicar, porque versões são identificadas pelo hash.
- Sobreposição configurável por fonte (`overlapMinutes`) para eventos atrasados.

## D6 — Horários em UTC

Banco, papéis, Logstash e índices trabalham em UTC. A conversão para o horário
local é feita apenas na apresentação (Kibana/Grafana).

## D7 — Segredos

- Client secret do Graph e senha do coletor: arquivos em `docker/secrets/` (Compose secrets).
- Senhas consumidas por Elastic/Logstash: `docker/.env` com `chmod 600`.
- Nada disso é versionado (`.gitignore`). Senhas de banco são entregues ao `psql`
  por variável de ambiente (`\getenv`), não por argumento.
- Próximo passo recomendado: trocar o client secret por certificado
  (`GRAPH_CERT_KEY_FILE` + `GRAPH_CERT_THUMBPRINT_SHA256` já suportados).

## D8 — PostgreSQL nativo em VM dedicada

Decisão do projeto. O coletor e o Logstash conectam com `sslmode=require`
(certificado autoassinado do Ubuntu). Para `verify-full`, emita um certificado
para a VM-PG e configure `PGSSLROOTCERT_FILE` no coletor e `sslrootcert` no Logstash.

A evolução oferece `postgres/configure-tls.sh` e mounts da CA nos dois
consumidores. O padrão `require` é preservado para instalações existentes;
ative `verify-full` seguindo `DEPLOY-EVOLUCAO.md`, sem fallback automático.

## D9 — Escopo de nomes e inventário

Hunting/inventário incluem `srv` ou `fisico`, excluindo sempre `note` ou `micro`,
sem distinção de caixa. O catálogo esperado não é uma allowlist de coleta.
DeviceInfo fornece estado conhecido dos últimos 30 dias; lista esperada vazia
significa cobertura total desconhecida. `SOCObserved` não é heartbeat online.
O estado atual fica em `soc.device_inventory` e `soc-devices`.

## D10 — Identidade e correlação

SID é evidência da identidade principal. As regras usam uma chave de correlação
de domínio+conta ou host+conta local/sem domínio, pois falhas podem não conter SID.
Ausência de SID/domínio não autoriza unir nomes iguais entre servidores.
Classificação pessoa/serviço só é preenchida por catálogo explícito; sufixo `$`
e autoridades conhecidas permitem classificar máquina/sistema.

## D11 — Métricas operacionais

JDBC de telemetria é independente do cursor xid8 da publicação. Snapshots por
minuto usam IDs por fonte/minuto. Gauges usam última amostra, nunca soma de
snapshots. Tamanho das relações PostgreSQL é medido sem varrer eventos; capacidade
do ES vem de `_nodes/_local/stats` autenticado com o usuário monitor do Logstash.
Os dados não representam CPU/RAM das VMs nem dos endpoints monitorados.
