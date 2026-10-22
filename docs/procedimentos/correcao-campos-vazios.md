# Correção: eventos recusados pelo Elasticsearch por colunas nulas `{}` (22/10/2026)

**Sintoma.** O painel "Acessos aos servidores" não mostrava acessos negados nem os
tipos Batch, NetworkCleartext, Service e NewCredentials; o Elasticsearch tinha cerca
de 27 % dos eventos de logon que estavam no PostgreSQL.

**Causa.** O Advanced Hunting, via Graph, devolve colunas nulas como objeto vazio
(`"LogonId": {}`, `"RemotePort": {}`, `"InitiatingProcessId": {}`, `"ProcessCreationTime": {}`).
O pipeline copiava esse `{}` para `winlog.logon.id`, `source.port`, `process.pid`,
`process.start` e afins, e o Elasticsearch recusava o documento inteiro
("Cannot parse object as number"). `ignore_malformed` não cobre objetos. As recusas
foram para a fila de rejeitados do Logstash (DLQ), que encheu (1 GB) em 21/10; a partir
daí as recusas passaram a ser descartadas.

**Dados não foram perdidos:** todos os eventos continuam em `soc.raw_event` no
PostgreSQL. A correção trata `{}` como ausente no `normalize.rb` e a republicação
reindexa o período.

## 1. VM do Docker — atualizar e liberar a fila de rejeitados

```bash
cd /home/administrator/soc_cerradao
git pull
cd docker
docker compose stop logstash
sudo mv /srv/soc/logstash-data/dead_letter_queue /srv/soc/logstash-data/dead_letter_queue.bak-20261022
docker compose up -d --no-deps logstash
docker compose ps logstash
```

O pipeline é montado do repositório; não precisa de rebuild. Guardamos a fila antiga
só para análise — apague-a depois de confirmar a correção (passo 4).

Confirme que o Logstash carregou os testes do pipeline sem falha:

```bash
docker compose logs logstash | grep 'Test run complete' | tail -1
```

Esperado: `failed: 0`.

## 2. VM do PostgreSQL — republicar os eventos

Republica todo o período retido. O procedimento confirma um dia por vez.

```bash
for t in DeviceLogonEvents DeviceEvents DeviceProcessEvents DeviceNetworkEvents; do
  sudo -u postgres psql -d soc -c "CALL soc.republish_events('$t', '2026-10-01', now() + interval '1 day')"
done
```

Tabelas que não existirem no seu ambiente apenas retornam 0 eventos.

## 3. Acompanhar a reindexação

VM do Docker — a contagem deve subir até se aproximar da do PostgreSQL:

```bash
docker compose exec es01 sh -c 'curl -s --cacert config/certs/ca/ca.crt -u "elastic:$ELASTIC_PASSWORD" "https://localhost:9200/_cat/indices/soc-events-*?v&h=index,docs.count"'
```

VM do PostgreSQL — total por tabela para comparar:

```bash
sudo -u postgres psql -d soc -c "SELECT table_name, count(*) FROM soc.raw_event GROUP BY 1 ORDER BY 1;"
```

Diferenças pequenas são esperadas (eventos fora do escopo de nomes de servidor
são filtrados no pipeline). Diferença grande indica nova recusa: veja o passo 4.

## 4. Confirmar que não há novas recusas

```bash
sudo du -sh /srv/soc/logstash-data/dead_letter_queue/
docker compose logs --since 30m logstash | grep -c 'Events could not be indexed'
```

Esperado: fila praticamente vazia e `0`. Depois de confirmado, apague a cópia antiga:

```bash
sudo rm -rf /srv/soc/logstash-data/dead_letter_queue.bak-20261022
```

## Efeitos colaterais esperados

- A republicação atualiza `event.ingested`; regras que usam esse campo (ASR e
  "termos novos") podem gerar uma leva de alertas nos 30 minutos seguintes. Em modo
  observação, nada é notificado; trate como ruído da reindexação.
- Os dashboards passam a mostrar negados, Batch, texto claro etc. também no
  histórico desde 01/10.

## Prevenção

- `normalize.rb` tem teste de regressão com o formato `{}` (rodado pelo Logstash na
  inicialização e pelo `scripts/validate.ps1`).
- Verifique periodicamente o tamanho da DLQ (passo 4). Fila crescendo = documentos
  sendo recusados; fila cheia = recusas descartadas sem registro.
