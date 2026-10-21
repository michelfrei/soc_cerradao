#!/usr/bin/env bash
# Prepara a VM do PostgreSQL 18 para o SOC.
#
# Uso (na VM do PostgreSQL, a partir da raiz do repositório):
#   sudo DOCKER_HOST_IP=10.0.0.20 PG_LISTEN_IP=10.0.0.10 ./postgres/setup-postgres.sh
#
# Variáveis:
#   DOCKER_HOST_IP  (obrigatória) IP da VM do Docker, única origem remota aceita.
#   PG_LISTEN_IP    (obrigatória) IP desta VM em que o PostgreSQL vai escutar.
#   ADMIN_CIDR      (opcional) rede de administração que poderá conectar com
#                   usuários do grupo soc_admins, ex.: 10.0.5.0/24.
#   CONFIGURE_UFW   (opcional, padrão 1) 0 para não mexer no firewall.
#   PG_VERSION      (opcional, padrão 18) PG_CLUSTER (opcional, padrão main).
#
# O que faz (idempotente):
#   1. Faz backup de pg_hba.conf e conf.d em /var/backups/soc-postgres/<data>.
#   2. Grava conf.d/10-soc.conf (escuta, TLS, SCRAM, UTC, logs, memória).
#   3. Substitui pg_hba.conf por regras restritas (só a VM do Docker remotamente).
#   4. Ajusta o ufw (SSH liberado; 5432 só da VM do Docker e de ADMIN_CIDR).
#   5. Reinicia o cluster, cria papéis e banco e aplica as migrações.
#   Senhas: geradas em /root/soc-secrets na primeira execução e reaproveitadas depois.
#
# Reversão: restaure os arquivos do backup e reinicie o cluster
#   (os comandos exatos são exibidos ao final).
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PG_VERSION="${PG_VERSION:-18}"
PG_CLUSTER="${PG_CLUSTER:-main}"
CONF_DIR="/etc/postgresql/${PG_VERSION}/${PG_CLUSTER}"
SECRETS_DIR=/root/soc-secrets
CONFIGURE_UFW="${CONFIGURE_UFW:-1}"

die() { echo "ERRO: $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "execute com sudo."
[[ -n "${DOCKER_HOST_IP:-}" ]] || die "defina DOCKER_HOST_IP."
[[ -n "${PG_LISTEN_IP:-}" ]] || die "defina PG_LISTEN_IP."
[[ "$DOCKER_HOST_IP" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || die "DOCKER_HOST_IP inválido."
[[ "$PG_LISTEN_IP" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || die "PG_LISTEN_IP inválido."
if [[ -n "${ADMIN_CIDR:-}" ]]; then
    [[ "$ADMIN_CIDR" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]{1,2}$ ]] || die "ADMIN_CIDR inválido."
fi
[[ -d "$CONF_DIR" ]] || die "cluster ${PG_VERSION}/${PG_CLUSTER} não encontrado em $CONF_DIR."
ip -4 addr show | grep -q "inet ${PG_LISTEN_IP}/" || die "PG_LISTEN_IP ${PG_LISTEN_IP} não pertence a esta VM."
command -v openssl >/dev/null || die "openssl não encontrado."

# O postgresql.conf do Ubuntu inclui conf.d; confirme antes de depender disso.
grep -Eq "^[[:space:]]*include_dir[[:space:]]*=[[:space:]]*'conf.d'" "$CONF_DIR/postgresql.conf" \
    || die "postgresql.conf não contém include_dir = 'conf.d'."

# 1. Backup ---------------------------------------------------------------------
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
BACKUP="/var/backups/soc-postgres/${STAMP}"
install -d -m 700 "$BACKUP"
cp -a "$CONF_DIR/pg_hba.conf" "$CONF_DIR/postgresql.conf" "$BACKUP/"
[[ -d "$CONF_DIR/conf.d" ]] && cp -a "$CONF_DIR/conf.d" "$BACKUP/"
echo "Backup em $BACKUP"

# 2. Configuração ---------------------------------------------------------------
MEM_MB=$(( $(awk '/MemTotal/ {print $2}' /proc/meminfo) / 1024 ))
SHARED_MB=$(( MEM_MB / 4 ))
CACHE_MB=$(( MEM_MB * 6 / 10 ))
install -d -o postgres -g postgres -m 755 "$CONF_DIR/conf.d"
cat > "$CONF_DIR/conf.d/10-soc.conf" <<EOF
# Gerado por setup-postgres.sh em ${STAMP}. Alterações manuais: use 20-local.conf.
listen_addresses = 'localhost,${PG_LISTEN_IP}'
ssl = on
password_encryption = 'scram-sha-256'

timezone = 'UTC'
log_timezone = 'UTC'
log_line_prefix = '%m [%p] %q%u@%d from %h app=%a '
log_connections = on
log_disconnections = on
log_lock_waits = on
log_min_duration_statement = '2s'

# Transações esquecidas abertas seguram o xmin e atrasam a publicação ao Logstash.
idle_in_transaction_session_timeout = '15min'

# Memória calculada para ${MEM_MB} MB de RAM. Durabilidade (fsync,
# synchronous_commit, full_page_writes) permanece no padrão.
shared_buffers = '${SHARED_MB}MB'
effective_cache_size = '${CACHE_MB}MB'
work_mem = '16MB'
maintenance_work_mem = '256MB'
wal_compression = on
checkpoint_timeout = '15min'
max_wal_size = '4GB'
EOF
chown postgres:postgres "$CONF_DIR/conf.d/10-soc.conf"
chmod 644 "$CONF_DIR/conf.d/10-soc.conf"

# 3. pg_hba.conf ----------------------------------------------------------------
{
    echo "# Gerado por setup-postgres.sh em ${STAMP}. Backup anterior: ${BACKUP}/pg_hba.conf"
    echo "# TYPE  DATABASE  USER            ADDRESS              METHOD"
    echo "local   all       postgres                             peer"
    echo "local   all       all                                  scram-sha-256"
    echo "host    all       all             127.0.0.1/32         scram-sha-256"
    echo "host    all       all             ::1/128              scram-sha-256"
    echo "hostssl soc       soc_collector   ${DOCKER_HOST_IP}/32 scram-sha-256"
    echo "hostssl soc       soc_logstash    ${DOCKER_HOST_IP}/32 scram-sha-256"
    if [[ -n "${ADMIN_CIDR:-}" ]]; then
        echo "hostssl all       +soc_admins     ${ADMIN_CIDR}        scram-sha-256"
    fi
} > "$CONF_DIR/pg_hba.conf.new"
chown postgres:postgres "$CONF_DIR/pg_hba.conf.new"
chmod 640 "$CONF_DIR/pg_hba.conf.new"
mv "$CONF_DIR/pg_hba.conf.new" "$CONF_DIR/pg_hba.conf"

echo "Diferenças em pg_hba.conf:"
diff -u "$BACKUP/pg_hba.conf" "$CONF_DIR/pg_hba.conf" || true

# 4. Firewall -------------------------------------------------------------------
if [[ "$CONFIGURE_UFW" == "1" ]]; then
    command -v ufw >/dev/null || die "ufw não encontrado (use CONFIGURE_UFW=0 para pular)."
    # Libera as portas em que o sshd realmente escuta (não presume a 22).
    ssh_ports="$(sshd -T 2>/dev/null | awk '$1 == "port" {print $2}' | sort -u)"
    [[ -n "$ssh_ports" ]] || ssh_ports=22
    for p in $ssh_ports; do
        ufw allow "${p}/tcp" >/dev/null
        echo "ufw: SSH liberado na porta $p"
    done
    if ufw status | grep -q '^Status: active'; then
        echo "ufw já estava ativo; regras existentes foram mantidas."
    fi
    ufw allow from "$DOCKER_HOST_IP" to any port 5432 proto tcp >/dev/null
    if [[ -n "${ADMIN_CIDR:-}" ]]; then
        ufw allow from "$ADMIN_CIDR" to any port 5432 proto tcp >/dev/null
    fi
    ufw --force enable >/dev/null
    ufw status verbose
fi

# 5. Aplicar: restart só se a configuração mudou (listen_addresses e memória
#    exigem restart); mudança apenas no pg_hba basta um reload. A linha de
#    cabeçalho com a data é ignorada na comparação.
SERVICE="postgresql@${PG_VERSION}-${PG_CLUSTER}"
conf_changed=1
if [[ -f "$BACKUP/conf.d/10-soc.conf" ]] && \
   diff -q <(tail -n +2 "$BACKUP/conf.d/10-soc.conf") <(tail -n +2 "$CONF_DIR/conf.d/10-soc.conf") >/dev/null; then
    conf_changed=0
fi
hba_changed=1
if diff -q <(grep -v '^#' "$BACKUP/pg_hba.conf") <(grep -v '^#' "$CONF_DIR/pg_hba.conf") >/dev/null; then
    hba_changed=0
fi

if [[ $conf_changed -eq 1 ]] || ! systemctl is-active --quiet "$SERVICE"; then
    echo "Reiniciando $SERVICE (configuração alterada)"
    systemctl restart "$SERVICE"
elif [[ $hba_changed -eq 1 ]]; then
    echo "Recarregando $SERVICE (pg_hba.conf alterado)"
    systemctl reload "$SERVICE"
else
    echo "Configuração sem mudanças; PostgreSQL não foi reiniciado."
fi
for _ in $(seq 1 30); do
    sudo -u postgres pg_isready -q && break
    sleep 1
done
sudo -u postgres pg_isready -q || die "PostgreSQL indisponível. Veja: journalctl -u ${SERVICE}"

# Senhas ------------------------------------------------------------------------
install -d -m 700 "$SECRETS_DIR"
for name in pg_collector_password pg_logstash_password; do
    if [[ ! -s "$SECRETS_DIR/$name" ]]; then
        (umask 077; openssl rand -hex 24 > "$SECRETS_DIR/$name")
    fi
done
SOC_COLLECTOR_PASSWORD="$(cat "$SECRETS_DIR/pg_collector_password")"
SOC_LOGSTASH_PASSWORD="$(cat "$SECRETS_DIR/pg_logstash_password")"
export SOC_COLLECTOR_PASSWORD SOC_LOGSTASH_PASSWORD

# Papéis, banco e migrações -----------------------------------------------------
sudo -u postgres --preserve-env=SOC_COLLECTOR_PASSWORD,SOC_LOGSTASH_PASSWORD \
    psql -X -q -v ON_ERROR_STOP=1 -d postgres -f - < "$DIR/bootstrap.sql"
unset SOC_COLLECTOR_PASSWORD SOC_LOGSTASH_PASSWORD

if [[ -n "${ADMIN_CIDR:-}" ]]; then
    sudo -u postgres psql -X -q -d postgres -c \
        "DO \$\$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'soc_admins') THEN CREATE ROLE soc_admins NOLOGIN; END IF; END \$\$;"
fi

bash "$DIR/migrate.sh"

cat <<EOF

Concluído.
- Senhas dos usuários do banco: $SECRETS_DIR (copie para a VM do Docker conforme docs/RUNBOOK.md).
- Teste a partir da VM do Docker:
    psql "host=${PG_LISTEN_IP} dbname=soc user=soc_collector sslmode=require" -c 'select 1'
- Reversão da configuração:
    sudo cp -a ${BACKUP}/pg_hba.conf ${CONF_DIR}/pg_hba.conf
    sudo rm ${CONF_DIR}/conf.d/10-soc.conf
    sudo systemctl restart postgresql@${PG_VERSION}-${PG_CLUSTER}
EOF
