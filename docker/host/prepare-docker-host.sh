#!/usr/bin/env bash
# Prepara a VM do Docker para o Elasticsearch e cria os diretórios persistentes.
# Uso (na VM do Docker, a partir da raiz do repositório):
#   sudo ./docker/host/prepare-docker-host.sh
# Os caminhos ES_DATA_DIR, ES_SNAPSHOT_DIR e LS_DATA_DIR são lidos de docker/.env.
# Variáveis opcionais: DISABLE_SWAP (padrão 1), CONFIGURE_UFW (padrão 0).
# Falha se docker/.env ou os arquivos de segredo do coletor estiverem ausentes.
set -euo pipefail

die() { echo "ERRO: $*" >&2; exit 1; }
[[ $EUID -eq 0 ]] || die "execute com sudo."

DOCKER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$DOCKER_DIR/.env"
SECRETS_DIR="$DOCKER_DIR/secrets"
[[ -f "$ENV_FILE" ]] || die "crie $ENV_FILE a partir de .env.example antes de preparar o host."

if grep -q $'\r' "$ENV_FILE"; then
    sed -i 's/\r$//' "$ENV_FILE"
    echo "Quebras de linha do Windows removidas de .env"
fi

# Lê uma chave do .env sem executar o arquivo.
env_value() {
    local v
    v="$(grep -E "^[[:space:]]*$1=" "$ENV_FILE" | tail -1 | cut -d= -f2-)"
    echo "${v:-$2}"
}

ES_DATA_DIR="$(env_value ES_DATA_DIR /srv/soc/esdata)"
ES_SNAPSHOT_DIR="$(env_value ES_SNAPSHOT_DIR /srv/soc/es-snapshots)"
LS_DATA_DIR="$(env_value LS_DATA_DIR /srv/soc/logstash-data)"
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
# Se o arquivo não existir quando o container for criado, o Docker cria um
# diretório no lugar e o coletor falha com EISDIR.
for f in graph_client_secret pg_collector_password; do
    p="$SECRETS_DIR/$f"
    if [[ -d "$p" ]]; then
        die "$p é um diretório (criado pelo Docker). Remova com 'rmdir $p', crie o arquivo e rode de novo."
    fi
    [[ -s "$p" ]] || die "crie $p (arquivo com o valor, sem quebra de linha extra) e rode de novo."
    chown 1000:1000 "$p"
    chmod 400 "$p"
    echo "Permissões ajustadas: secrets/$f"
done
chmod 600 "$ENV_FILE"

if [[ "$CONFIGURE_UFW" == "1" ]]; then
    command -v ufw >/dev/null || die "ufw não encontrado."
    ufw allow OpenSSH >/dev/null
    ufw --force enable >/dev/null
    echo "ufw habilitado com SSH liberado."
fi
# Portas publicadas pelo Docker (Kibana 5601, Elasticsearch 9200) NÃO passam pelo ufw.
# Restrinja pelo bind no .env (ES_BIND/KIBANA_BIND) e pelo firewall de rede.
echo "Exposição: KIBANA_BIND=$(env_value KIBANA_BIND 0.0.0.0) ES_BIND=$(env_value ES_BIND 127.0.0.1)"
echo "Docker habilitado no boot: $(systemctl is-enabled docker 2>/dev/null || echo desconhecido)"

mem_mb=$(( $(awk '/MemTotal/ {print $2}' /proc/meminfo) / 1024 ))
echo "RAM da VM: ${mem_mb} MB (recomendado >= 12288 MB para o piloto)"
echo "Lembrete: desative a memória dinâmica desta VM no Hyper-V."
echo "Preparação concluída."
