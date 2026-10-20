#!/usr/bin/env bash
# Prepara a VM do Docker para o Elasticsearch e cria os diretórios persistentes.
# Uso (na VM do Docker, a partir da raiz do repositório):
#   sudo ./docker/host/prepare-docker-host.sh
# Variáveis opcionais: ES_DATA_DIR, ES_SNAPSHOT_DIR, LS_DATA_DIR (mesmos valores do .env),
#                      DISABLE_SWAP (padrão 1), CONFIGURE_UFW (padrão 0), ADMIN_CIDR.
set -euo pipefail

die() { echo "ERRO: $*" >&2; exit 1; }
[[ $EUID -eq 0 ]] || die "execute com sudo."

ES_DATA_DIR="${ES_DATA_DIR:-/srv/soc/esdata}"
ES_SNAPSHOT_DIR="${ES_SNAPSHOT_DIR:-/srv/soc/es-snapshots}"
LS_DATA_DIR="${LS_DATA_DIR:-/srv/soc/logstash-data}"
DISABLE_SWAP="${DISABLE_SWAP:-1}"
CONFIGURE_UFW="${CONFIGURE_UFW:-0}"

command -v docker >/dev/null || die "Docker não encontrado."
docker compose version >/dev/null 2>&1 || die "plugin docker compose não encontrado."

# vm.max_map_count: mínimo exigido pelo Elasticsearch.
current="$(sysctl -n vm.max_map_count)"
if (( current < 262144 )); then
    echo "vm.max_map_count=262144" > /etc/sysctl.d/99-soc-elasticsearch.conf
    sysctl -q -p /etc/sysctl.d/99-soc-elasticsearch.conf
    echo "vm.max_map_count ajustado para 262144"
else
    echo "vm.max_map_count já é ${current}"
fi

# Swap: o Elasticsearch perde desempenho e estabilidade quando a heap vai para o disco.
if [[ "$DISABLE_SWAP" == "1" ]]; then
    if [[ -n "$(swapon --show --noheadings)" ]]; then
        swapoff -a
        cp -a /etc/fstab "/etc/fstab.soc-backup-$(date -u +%Y%m%dT%H%M%SZ)"
        sed -ri '/^[^#].*[[:space:]]swap[[:space:]]/ s/^/# desativado pelo SOC: /' /etc/fstab
        echo "Swap desativado (backup do fstab criado)"
    else
        echo "Swap já está desativado"
    fi
fi

# Diretórios persistentes: Elasticsearch e Logstash rodam com uid 1000 e gid 0.
for d in "$ES_DATA_DIR" "$ES_SNAPSHOT_DIR" "$LS_DATA_DIR"; do
    install -d -o 1000 -g 0 -m 770 "$d"
    echo "$d -> $(findmnt -n -o SOURCE,TARGET,FSTYPE -T "$d")"
done

# Segredos do coletor: o container roda como usuário node (uid 1000).
SECRETS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/secrets"
for f in graph_client_secret pg_collector_password; do
    if [[ -f "$SECRETS_DIR/$f" ]]; then
        chown 1000:1000 "$SECRETS_DIR/$f"
        chmod 400 "$SECRETS_DIR/$f"
        echo "Permissões ajustadas: secrets/$f"
    else
        echo "AVISO: crie $SECRETS_DIR/$f antes de subir o coletor."
    fi
done
if [[ -f "$SECRETS_DIR/../.env" ]]; then
    chmod 600 "$SECRETS_DIR/../.env"
fi

if [[ "$CONFIGURE_UFW" == "1" ]]; then
    command -v ufw >/dev/null || die "ufw não encontrado."
    ufw allow OpenSSH >/dev/null
    if [[ -n "${ADMIN_CIDR:-}" ]]; then
        ufw allow from "$ADMIN_CIDR" to any port 5601 proto tcp >/dev/null
    else
        ufw allow 5601/tcp >/dev/null
    fi
    ufw --force enable >/dev/null
    echo "AVISO: portas publicadas pelo Docker não passam pelas regras do ufw;"
    echo "       o controle efetivo é o bind configurado no .env (ES_BIND/KIBANA_BIND)."
fi

mem_mb=$(( $(awk '/MemTotal/ {print $2}' /proc/meminfo) / 1024 ))
echo "RAM da VM: ${mem_mb} MB (recomendado >= 12288 MB para o piloto)"
echo "Lembrete: desative a memória dinâmica desta VM no Hyper-V."
echo "Preparação concluída."
