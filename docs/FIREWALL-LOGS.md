# Logs da firewall (FortiGate via FortiAnalyzer)

Os logs do FortiGate 100F chegam ao Elastic pelo FortiAnalyzer, que já recebe todos eles. O
PostgreSQL guarda só agregados por hora, para cruzar com o Defender.

```
FortiGate ──► FortiAnalyzer ── syslog TCP + TLS (reliable), porta 6514 ──►
VM-Docker: syslog-relay (TLS, RFC 6587, só o IP do FortiAnalyzer)
   └─ rede interna ──► Logstash, pipeline "fortigate" (fila própria em disco de 8 GB)
         └─► Elasticsearch: data stream fw-logs-fortigate (ECS, 30 dias)
                 └─► coletor, fonte fwflows (de hora em hora) ──► PostgreSQL soc.fw_flow_hourly
                        └─► publicação (cursor xid8) ──► Logstash ──► soc-fw-flows-AAAA.MM
```

| Peça | Onde | Função |
|---|---|---|
| `syslog-relay/` | VM-Docker, porta 6514 publicada | Termina o TLS, aceita só os IPs de `FW_SYSLOG_ALLOWED`, separa as mensagens (contagem de octetos ou LF) e entrega uma por linha ao Logstash |
| `logstash/pipeline/fortigate.conf` + `fortigate.rb` | Logstash, porta 5514 só na rede interna | Interpreta chave=valor, converte para ECS, calcula `soc.fw.verdict` e `network.direction` e descarta campos redundantes |
| `fw-logs-fortigate` | Elasticsearch | Data stream com mapeamento explícito, `best_compression`, rollover diário e exclusão após 30 dias |
| Fonte `fwflows.fortigate` | Coletor | Agrega cada hora no Elasticsearch (por origem, e fluxos de/para 172.16.159.0/24), grava em `soc.fw_flow_hourly` (30 dias) e publica `soc-fw-flows-*` (395 dias) |
| Dashboard **SOC - Firewall** | Kibana | Bloqueios, políticas, entradas da internet, países, origens e fluxos dos servidores |

## Dimensionamento (amostra de 27/10/2026)

A exportação do FortiAnalyzer trouxe 52.224 sessões em 6 minutos (14:50–14:56): **cerca de 150
por segundo** no horário comercial, com 1,45 KB por linha.

| Item | Estimativa |
|---|---|
| Sessões por dia | 6 a 9 milhões |
| Texto bruto por dia | 9 a 13 GB |
| Elasticsearch (campos descartados + compressão) | 4 a 6 GB/dia, **120 a 180 GB em 30 dias** |
| PostgreSQL (agregados) | dezenas de milhares de linhas por dia |
| Fila do Logstash | 8 GB em `LS_DATA_DIR`, cerca de 6 h de pico se o Elasticsearch parar |

Confirme o volume real de 24 h no widget **Log Receive Monitor** do FortiAnalyzer. Deixe
**250 GB livres** em `ES_DATA_DIR`. Se faltar disco, reduza o `delete.min_age` em
`elasticsearch/ilm/fw-logs-retention.json` ou filtre tipos de log no FortiAnalyzer.

## Campos principais

| Campo | Origem no FortiOS | Observação |
|---|---|---|
| `@timestamp` | `eventtime` (ns/µs/ms/s); sem ele, `date`+`time`+`tz` | horário da firewall, em UTC |
| `source.*` / `destination.*` | `srcip`, `srcport`, `srcmac`, `sentbyte`… / `dstip`, `dstport`, `hostname`, `rcvdbyte`… | `source.nat.*` = `transip`/`transport` |
| `event.action` | `action` | accept, close, client-rst, server-rst, deny, timeout |
| `soc.fw.verdict` | `action` deny ou `utmaction` block | `blocked` ou `allowed`, só em tráfego e UTM |
| `network.direction` | `srcintfrole` → `dstintfrole` | lan→wan `outbound`, wan→lan `inbound`, sem wan `internal` |
| `rule.id` / `rule.name` | `policyid` / `policyname` | |
| `user.name` | `user` | dado pessoal |
| `fortinet.firewall.*` | `catdesc`, `appcat`, `utmaction`, `srcname`, `sessionid`, `attack`, `virus`… | |

Ficam de fora: `id`, `itime`, `dtime`, `date`/`time` (já em `@timestamp`), `logver`, `utmref`,
`mastersrcmac`, `masterdstmac`, `euid`/`epid`, `vwlquality`, `dstregion`, `dstcity` e a linha
original. Para guardar mais um campo, inclua-o em `FIELDS` (`fortigate.rb`) e no mapeamento
`fw-logs-mappings.json`.

## Dado pessoal (LGPD)

Usuário, MAC e sites acessados identificam pessoas. Por isso:
- os logs brutos ficam num nome fora de `soc-*` (`fw-logs-*`), legível só por `soc_admin`,
  `soc_analyst` e o usuário de leitura do coletor (`soc_collector_es`). `soc_observer` e
  `soc_reader` não os leem, e os painéis com logs brutos aparecem vazios para eles;
- a retenção dos brutos é de 30 dias;
- o uso deve ser investigação de segurança. Se a política interna exigir, o FortiAnalyzer
  pode mascarar campos no encaminhamento (`log-masking-*`).

---

# Implantação

Faça as etapas na ordem. **FAZ** = FortiAnalyzer, **VM-Docker** = 172.16.159.60,
**VM-PG** = 172.16.159.61.

## 1. VM-Docker: .env e segredo do coletor

Na pasta `docker/`, depois do `git pull`:

```bash
openssl rand -hex 24 | tr -d '\n' > secrets/es_collector_password && chmod 600 secrets/es_collector_password
```

No `.env`, acrescente as linhas abaixo e ajuste os valores. Copie a senha do arquivo com o
editor, sem colar em chat:
- `SOC_ES_COLLECTOR_PASSWORD=` recebe o conteúdo de `secrets/es_collector_password`.
- `FW_SYSLOG_ALLOWED=` recebe o IP do FortiAnalyzer (o de origem dos envios).
- `SOC_SYSLOG_IP=172.16.159.60` vai no certificado do relay.
- `COLLECTOR_VERSION=0.5.0`.

## 2. VM-PG: migração 007

```bash
sudo bash postgres/migrate.sh
```

Cria `soc.fw_flow_hourly` e permite a entidade `fwflow` na publicação.

## 3. VM-Docker: certificado, Elasticsearch, Logstash, relay e coletor

```bash
docker compose run --rm certs
docker compose run --rm setup
docker compose build logstash syslog-relay collector
docker compose up -d --no-deps logstash
docker compose up -d --no-deps syslog-relay collector
docker compose run --rm kibana-setup
docker compose ps
```

Esses comandos fazem o seguinte:
- `certs` emite só o certificado `syslog`, com a mesma CA, e não mexe nos certificados
  existentes.
- `setup` cria a política `fw-logs-retention`, os templates e o papel de escrita em
  `fw-logs-*`. Também cria o usuário `soc_collector_es`.
- O Logstash recriado carrega a pipeline `fortigate`. Se um teste Ruby de `fortigate.rb`
  falhar, a pipeline não sobe: veja `docker compose logs logstash`.

Confira os logs do relay e da pipeline:

```bash
docker compose logs --tail 20 syslog-relay
```

```bash
docker compose logs --tail 50 logstash | grep -i fortigate
```

As portas publicadas pelo Docker não passam pelo ufw. O relay já recusa origens fora da
lista. Para bloquear também na rede, use o firewall de rede ou a cadeia `DOCKER-USER`
(regra não persistente, troque o IP):

```bash
sudo iptables -I DOCKER-USER -p tcp --dport 6514 ! -s <IP_DO_FAZ> -j DROP
```

## 4. FortiAnalyzer: encaminhamento de logs

**Pela GUI:** *System Settings → Advanced → Log Forwarding → Create New*:
- **Name:** `soc-elastic`. **Remote Server Type:** Syslog.
- **Server Address:** 172.16.159.60. **Server Port:** 6514. **Reliable Connection:** ligado.
- **Device Filter:** o FortiGate `CERRADAO_FG100F`.
- **Log Filters:** tipo traffic, mais UTM e event se quiser. Comece com traffic + event.

O TLS (`fwd-secure`) só se liga pela CLI. Faça os ajustes na mesma entrada:

```
config system log-forward
    edit <id da entrada soc-elastic>
        set fwd-reliable enable
        set fwd-secure enable
        set fwd-max-delay realtime
        set fwd-syslog-format fgt
        set fwd-compression disable
    next
end
```

Nomes e opções conferidos na referência de CLI do FortiAnalyzer 7.2. Na sua versão,
confirme com `?` antes de cada `set`. O FAZ, como cliente TLS, apresenta o certificado
OFTP dele. A conferência do certificado do relay pelo FAZ (`peer-cert-cn syslog` e a CA
importada no FAZ) é opcional. A CA está em `docker` → volume `certs_public` (`ca.crt`).

## 5. Conferir os logs brutos

- `docker compose logs syslog-relay` deve mostrar "emissor conectado" com o IP do FAZ e,
  a cada minuto, `messages` crescendo.
- Em Kibana → Discover → data view **SOC - Firewall (logs do FortiGate)**, os documentos devem
  ter `event.dataset: fortigate.traffic`.
- Sem documentos: veja `docker compose logs logstash` (erros 403 = papel; recusas de
  mapeamento vão para a DLQ).
- Documentos com a tag `_fortigate_sem_horario` indicam formato de horário inesperado: me
  mande um exemplo sem dados pessoais.
- Se o relay mostrar o IP do gateway Docker em vez do IP do FAZ, o `userland-proxy` está
  escondendo a origem. Coloque esse IP em `FW_SYSLOG_ALLOWED` provisoriamente e avise.

## 6. Ligar os agregados (coletor)

Com logs chegando há pelo menos 1 hora, em `collector/config/sources.json` troque
`"enabled": false` por `true` na fonte `fwflows.fortigate`. Ajuste `serverCidrs` se houver
outras redes de servidores. Depois reinicie o coletor:

```bash
docker compose restart collector
```

A primeira execução calcula as últimas 24 h. Confira a fonte `fwflows.fortigate` na tabela de
execuções (**Cobertura e capacidade**) e o painel **SOC - Firewall** (tabela de servidores).
No PostgreSQL, como `soc_diag`:

```sql
SELECT kind, count(*), min(hour), max(hour) FROM soc.fw_flow_hourly GROUP BY kind;
```

## Reversão

- **Parar a ingestão:** desative a entrada no FortiAnalyzer ou
  `docker compose stop syslog-relay`. O FAZ mantém o que não conseguiu enviar na própria fila.
- **Agregados:** `enabled: false` na fonte e reinicie o coletor.
- A migração 007 é aditiva e pode ficar.
- Não apague o data stream sem decidir a retenção. Para remover os dados brutos, apague
  `fw-logs-fortigate` no Kibana (Index Management), com confirmação de quem responde pelo SOC.
