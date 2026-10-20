# Runbook — piloto no Hyper-V

Duas VMs Ubuntu 26.04:

| VM | Função | Portas de entrada |
|---|---|---|
| **VM-PG** | PostgreSQL 18 nativo | 5432 apenas a partir da VM-Docker (e `ADMIN_CIDR`, se definido) |
| **VM-Docker** | Elasticsearch, Kibana, Logstash e coletor (Compose) | 5601 (Kibana, HTTPS); 9200 só local por padrão |

Fluxo: Graph → coletor → PostgreSQL (`soc.publication`) → Logstash → Elasticsearch → Kibana.

> Convenções: comandos executados na raiz do repositório clonado em cada VM.
> Nenhuma senha deve aparecer em argumentos de comando, chats ou tickets.

---

## 0. Antes de começar (Hyper-V)

- [ ] VM-Docker: **memória dinâmica desativada**, ≥ 12 GB de RAM (16 GB recomendado), 4 vCPU.
- [ ] VM-PG: se a intenção é validar o SAS, o **VHDX está no volume SAS** do host. Prefira VHDX de tamanho fixo.
- [ ] As duas VMs se enxergam (ping/IP fixo) e a VM-Docker tem saída HTTPS para
      `login.microsoftonline.com` e `graph.microsoft.com` (direta ou por proxy).
- [ ] Checkpoints do Hyper-V **não** substituem backup do PostgreSQL.

## 1. VM-PG — PostgreSQL

```bash
git clone <url-do-repositorio> soc && cd soc
sudo DOCKER_HOST_IP=<ip-vm-docker> PG_LISTEN_IP=<ip-vm-pg> ./postgres/setup-postgres.sh
```

Opcional: `ADMIN_CIDR=<rede-admin>/24` libera acesso para membros de `soc_admins`;
`CONFIGURE_UFW=0` se o firewall for gerido por outro meio.

O script:
- faz backup de `pg_hba.conf` e `postgresql.conf` em `/var/backups/soc-postgres/<data>`;
- **substitui o `pg_hba.conf`** (a configuração permissiva atual deixa de valer — o diff é exibido);
- grava `conf.d/10-soc.conf` (escuta, TLS, SCRAM, UTC, logs, memória);
- habilita o ufw com SSH liberado e 5432 restrito;
- cria `soc_owner`, `soc_collector`, `soc_logstash`, o banco `soc` e aplica as migrações;
- gera as senhas em `/root/soc-secrets/` (somente root).

Verificação:

```bash
sudo -u postgres psql -d soc -c "table soc.schema_migrations"
sudo -u postgres psql -d soc -c "\dt soc.*"
sudo ufw status
```

Novas migrações no futuro: `git pull && sudo ./postgres/migrate.sh`.

## 2. Transferir as senhas do banco para a VM-Docker

Na VM-PG, exiba cada senha e copie pelo terminal (ou use `scp` entre as VMs):

```bash
sudo cat /root/soc-secrets/pg_collector_password
sudo cat /root/soc-secrets/pg_logstash_password
```

- `pg_collector_password` → arquivo `docker/secrets/pg_collector_password` na VM-Docker.
- `pg_logstash_password` → variável `SOC_LOGSTASH_DB_PASSWORD` no `docker/.env`.

## 3. VM-Docker — configuração

```bash
git clone <url-do-repositorio> soc && cd soc/docker
cp .env.example .env && chmod 600 .env
```

Preencha o `.env`:

| Variável | Valor |
|---|---|
| `STACK_VERSION` | versão exata da Elastic Stack (padrão 9.5.5, a mais recente no registro em 20/10/2026) |
| `SOC_PUBLIC_IP` / `KIBANA_PUBLIC_URL` | IP da VM-Docker |
| `SOC_PG_HOST` | IP da VM-PG |
| `ELASTIC_PASSWORD`, `KIBANA_PASSWORD`, `SOC_ES_LOGSTASH_PASSWORD` | `openssl rand -hex 24` (uma para cada) |
| `KIBANA_*_KEY` (3) | `openssl rand -hex 32` (uma para cada) |
| `GRAPH_TENANT_ID`, `GRAPH_CLIENT_ID` | IDs do app no Entra ID |

Segredos do coletor (o editor evita que o valor fique no histórico do shell):

```bash
nano secrets/graph_client_secret      # cole o client secret do app (só o valor)
nano secrets/pg_collector_password    # cole a senha do soc_collector
```

Prepare o host (sysctl, swap, diretórios e permissões dos segredos):

```bash
sudo ../docker/host/prepare-docker-host.sh
```

Confira se `/srv/soc/*` está no disco desejado (o script mostra o `findmnt`).

## 4. Teste de conectividade com o PostgreSQL

```bash
docker run --rm -it postgres:18 psql "host=<ip-vm-pg> dbname=soc user=soc_collector sslmode=require" -c "select current_user"
```

Deve pedir a senha e retornar `soc_collector`. Se falhar, veja a seção 9.

## 5. Subir a stack

```bash
docker compose up -d --build
docker compose ps
```

Ordem esperada: `setup` gera certificados e termina com `Exited (0)`; `es01`, `kibana`
e `logstash` ficam `healthy`; `collector` fica `healthy` após conectar ao banco.

```bash
docker compose logs setup          # deve terminar com "Setup concluído"
docker compose logs -f collector   # "coleta concluída" para incidents e alerts
docker compose logs -f logstash
```

## 6. Validação da primeira coleta (somente incidentes e alertas)

Na VM-PG:

```sql
-- sudo -u postgres psql -d soc
SELECT * FROM soc.v_collector_status;
SELECT kind, count(*) FROM soc.security_object GROUP BY kind;
SELECT entity, count(*) FROM soc.publication GROUP BY entity;
```

Na VM-Docker:

```bash
curl -s --cacert <(docker compose exec -T es01 cat config/certs/ca/ca.crt) \
     -u elastic https://localhost:9200/_cat/indices/soc-*?v
```

No Kibana (`https://<ip-vm-docker>:5601`, usuário `elastic`):
1. **Stack Management → Data Views**: crie `soc-incidents`, `soc-alerts`, `soc-events-*`
   (campo de tempo `@timestamp`).
2. **Discover**: compare a contagem com o portal do Defender no mesmo período.
3. Crie usuários nominais para os analistas com o papel `soc_reader` e
   evite usar `elastic` no dia a dia.

O certificado do Kibana é da CA interna gerada no setup. Para evitar o alerta do
navegador, importe a CA (`docker compose exec es01 cat config/certs/ca/ca.crt`)
nas estações dos analistas.

Critérios de aceite desta etapa:

| Critério | Como verificar |
|---|---|
| Incidentes e alertas chegam ao PostgreSQL | `soc.security_object` com contagens coerentes com o portal |
| Repetir a coleta não duplica | `changed = 0` em execuções seguintes sem mudança no Defender |
| Atualização no Defender gera nova versão | Altere status/atribuição de um incidente de teste e confira `security_object_version` |
| Dados pesquisáveis no Kibana | Índices `soc-incidents` e `soc-alerts` com os mesmos totais |
| Reinício não perde progresso | `docker compose restart collector logstash` e conferir que o checkpoint continua |

## 7. Habilitar Advanced Hunting (depois da etapa 6)

1. Em `collector/queries/devicelogonevents.kql`, restrinja aos servidores do piloto
   (linha `DeviceName in~`), se desejar.
2. Em `collector/config/sources.json`, mude `"enabled": true` em `hunting.devicelogonevents`.
3. `docker compose restart collector` (arquivos montados; não precisa de rebuild).
4. Acompanhe `throttled` e `fetched` em `soc.v_collector_status`. Habilite `hunting.asr` em seguida.

Os eventos aparecem em `soc-events-devicelogonevents-AAAA.MM` e `soc-events-deviceevents-AAAA.MM`.

## 8. Operação

| Tarefa | Comando |
|---|---|
| Situação da coleta | `SELECT * FROM soc.v_collector_status;` |
| Execuções com falha | `SELECT * FROM soc.collector_run WHERE status = 'failed' ORDER BY id DESC LIMIT 20;` |
| Reindexar um período | `SELECT soc.republish_events('DeviceLogonEvents', '2026-10-01', '2026-10-02');` (como `soc_owner`) |
| Recoletar desde uma data | `UPDATE soc.collector_checkpoint SET watermark = '<data>' WHERE source = '<fonte>';` e reiniciar o coletor (o Advanced Hunting só retém 30 dias) |
| Limpar publicações antigas | `SET ROLE soc_owner; SELECT soc.purge_publication('7 days');` |
| Documentos rejeitados | DLQ do Logstash em `/srv/soc/logstash-data/dead_letter_queue` |
| Atualizar templates do ES | edite `elasticsearch/` e rode `docker compose run --rm setup` |

Backup (próxima etapa do projeto): `pg_dump`/pgBackRest da VM-PG e snapshots do
Elasticsearch em `ES_SNAPSHOT_DIR`, ambos com destino fora das VMs.

## 9. Problemas comuns

| Sintoma | Causa provável |
|---|---|
| `collector` reinicia com erro de leitura de segredo | Arquivo ausente ou dono diferente de uid 1000: rode `prepare-docker-host.sh` de novo |
| `no pg_hba.conf entry` | IP de origem diferente de `DOCKER_HOST_IP` (NAT/rota) ou `sslmode` desativado |
| `401`/`403` no Graph | Secret expirado, permissão sem consentimento administrativo ou tenant errado |
| `throttled` crescendo | Reduza `GRAPH_MAX_CONCURRENCY` ou aumente `intervalSeconds` |
| Publicação parada | Transação longa aberta no PostgreSQL segurando o xmin: `SELECT pid, xact_start, state FROM pg_stat_activity WHERE backend_xid IS NOT NULL OR backend_xmin IS NOT NULL;` |
| `es01` não sobe | `vm.max_map_count`, permissões de `/srv/soc/esdata` (1000:0) ou falta de RAM |

## 10. Reversão

- Stack: `docker compose down` (mantém os dados em `/srv/soc` e volumes).
  `docker compose down -v` também apaga certificados e dados do Kibana.
- PostgreSQL: comandos exibidos ao final do `setup-postgres.sh` (restauram o
  `pg_hba.conf` anterior e removem `conf.d/10-soc.conf`).
- Banco: `DROP DATABASE soc;` e os papéis `soc_*` (somente se quiser recomeçar do zero).
