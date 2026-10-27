# Logs da firewall (FortiGate via FortiAnalyzer)

Os logs do FortiGate 100F chegam ao Elastic pelo FortiAnalyzer, que já recebe todos eles. O
PostgreSQL guarda só agregados por hora, para cruzar com o Defender.

```
FortiGate ──► FortiAnalyzer ── syslog TCP + TLS (reliable), porta 6514 ──►
VM-Docker: syslog-relay (TLS, RFC 6587, só o IP do FortiAnalyzer)
   └─ rede interna ──► Logstash, pipeline "fortigate" (fila própria em disco de 4 GB)
         └─► Elasticsearch: data stream fw-logs-fortigate (ECS, 10 dias)
                 └─► coletor, fonte fwflows (de hora em hora) ──► PostgreSQL soc.fw_flow_hourly
                        └─► publicação (cursor xid8) ──► Logstash ──► soc-fw-flows-AAAA.MM
```

| Peça | Onde | Função |
|---|---|---|
| `syslog-relay/` | VM-Docker, porta 6514 publicada | Termina o TLS, aceita só os IPs de `FW_SYSLOG_ALLOWED`, separa as mensagens (contagem de octetos ou LF) e entrega uma por linha ao Logstash |
| `logstash/pipeline/fortigate.conf` + `fortigate.rb` | Logstash, porta 5514 só na rede interna | Interpreta chave=valor, converte para ECS, calcula `soc.fw.verdict` e `network.direction` e descarta campos redundantes |
| `fw-logs-fortigate` | Elasticsearch | Data stream com mapeamento explícito, `best_compression`, rollover diário e exclusão após 10 dias (30 após ampliar o disco) |
| Fonte `fwflows.fortigate` | Coletor | Agrega cada hora no Elasticsearch (por origem, e fluxos de/para 172.16.159.0/24), grava em `soc.fw_flow_hourly` (30 dias) e publica `soc-fw-flows-*` (395 dias) |
| Fonte `fwsessions.fortigate` | Coletor | A cada 5 min, monta o estado das sessões de VPN e de administração (últimos 7 dias de logs), grava em `soc.fw_session_state` e publica `soc-fw-sessions` |
| Dashboard **SOC - Firewall** | Kibana | Bloqueios, políticas, entradas da internet, países, origens e fluxos dos servidores |
| Dashboard **SOC - Firewall: acessos e VPN** | Kibana | Sessões abertas agora, logins administrativos (sucesso e falha) e conexões VPN |

## Dimensionamento (amostra de 27/10/2026)

A exportação do FortiAnalyzer trouxe 52.224 sessões em 6 minutos (14:50–14:56): **cerca de 150
por segundo** no horário comercial, com 1,45 KB por linha.

| Item | Estimativa |
|---|---|
| Sessões por dia | 6 a 9 milhões |
| Texto bruto por dia | 9 a 13 GB |
| Elasticsearch (campos descartados + compressão) | 4 a 6 GB/dia: **40 a 60 GB em 10 dias**, 120 a 180 GB em 30 |
| PostgreSQL (agregados) | dezenas de milhares de linhas por dia |
| Fila do Logstash | 4 GB em `LS_DATA_DIR`, cerca de 5 h de pico se o Elasticsearch parar |

Confirme o volume real de 24 h no widget **Log Receive Monitor** do FortiAnalyzer. Em
27/10/2026 a VM-Docker tinha 98 GB de disco (69 GB livres), por isso a retenção começou em
**10 dias**. Para voltar a 30 dias, amplie o disco (250 GB livres em `ES_DATA_DIR`) e troque
`delete.min_age` para `30d` em `elasticsearch/ilm/fw-logs-retention.json`. Depois rode
`docker compose run --rm setup`; a política nova vale também para os índices existentes.

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

## Acessos, VPN e sessões abertas

O Logstash marca os eventos de acesso (tipo `event`) com campos próprios:

| Evento do FortiOS | `soc.fw.access.kind` | Sessão (`soc.fw.session.id` / `state`) |
|---|---|---|
| `subtype=system`, `action=login`/`logout` (logids 32001 sucesso, 32002 falha, 32003 logout) | `admin` | `admin|<devid>|<sn>`: o `sn` liga o login ao logout. Só login com sucesso abre. |
| `subtype=vpn`, `tunnel-up` / `tunnel-down` / `tunnel-stats` | `vpn` | `vpn|<devid>|<tunnelid>` (IPsec sem tunnelid: `vpntunnel|remip`); abre, fecha, renova |
| `subtype=vpn`, `ssl-login-fail` ou status de falha | `vpn` | não abre sessão; `soc.fw.access.outcome: failure` |

`soc.fw.access.user` é a conta do FortiGate (`user` ou `xauthuser`); `soc.fw.access.channel` é
https/ssh/console (admin) ou ssl/ipsec (VPN).

**Sessões abertas** são as que não têm fechamento. O coletor recalcula a cada 5 minutos os
últimos 7 dias de logs; o painel não depende do seletor de tempo. Os estados:
- **open:** aberta e com evento dentro do limite.
- **stale** (sem fechamento registrado): aberta há mais de 72 h (VPN) ou 24 h (admin) sem
  evento novo. Pode ter caído sem log; confira no FortiGate.
- **closed:** encerrada.
- **unknown:** saiu da janela de 7 dias sem fechamento.

O total de sessões de tráfego da firewall (tabela de sessões) não vem nos logs e não aparece
aqui. Se precisar, dá para consultar `get system session status` pelo fgt-gateway.

Para os painéis de acesso, o FortiAnalyzer precisa encaminhar os logs do tipo **event**
(subtipos system e vpn), além de traffic.

## Dado pessoal (LGPD)

Usuário, MAC e sites acessados identificam pessoas. Por isso:
- os logs brutos ficam num nome fora de `soc-*` (`fw-logs-*`), legível só por `soc_admin`,
  `soc_analyst` e o usuário de leitura do coletor (`soc_collector_es`). `soc_observer` e
  `soc_reader` não os leem, e os painéis com logs brutos aparecem vazios para eles;
- a retenção dos brutos é de 10 dias (30 depois de ampliar o disco);
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

## 2. VM-PG: migrações 007 e 008

```bash
sudo bash postgres/migrate.sh
```

A 007 cria `soc.fw_flow_hourly` e a 008 cria `soc.fw_session_state`. As duas permitem as
entidades `fwflow` e `fwsession` na publicação.

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
- **Log Filters:** tipos **traffic** e **event**. O event traz os logins administrativos e a
  VPN, usados no painel de acessos. UTM é opcional.

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

## 6. Agregados por hora (coletor)

A fonte `fwflows.fortigate` já vem ligada (desde 27/10/2026) e roda vazia até os logs chegarem;
a cada hora recalcula também a hora anterior. Ajuste `serverCidrs` em
`collector/config/sources.json` se houver outras redes de servidores e reinicie o coletor:

```bash
docker compose restart collector
```

A primeira execução calcula as últimas 24 h. Confira a fonte `fwflows.fortigate` na tabela de
execuções (**Cobertura e capacidade**) e o painel **SOC - Firewall** (tabela de servidores).
No PostgreSQL, como `soc_diag`:

```sql
SELECT kind, count(*), min(hour), max(hour) FROM soc.fw_flow_hourly GROUP BY kind;
```

## 7. Estado das sessões (coletor)

A fonte `fwsessions.fortigate` já vem ligada e depende da migração 008. A cada 5 minutos, o
painel **SOC - Firewall: acessos e VPN** passa a mostrar as sessões abertas.
No PostgreSQL, como `soc_diag`:

```sql
SELECT kind, state, count(*) FROM soc.fw_session_state GROUP BY kind, state ORDER BY 1, 2;
```

## Reversão

- **Parar a ingestão:** desative a entrada no FortiAnalyzer ou
  `docker compose stop syslog-relay`. O FAZ mantém o que não conseguiu enviar na própria fila.
- **Agregados e sessões:** `enabled: false` nas fontes `fwflows.fortigate` e `fwsessions.fortigate` e reinicie o coletor.
- As migrações 007 e 008 são aditivas e podem ficar.
- Não apague o data stream sem decidir a retenção. Para remover os dados brutos, apague
  `fw-logs-fortigate` no Kibana (Index Management), com confirmação de quem responde pelo SOC.
