#!/usr/bin/env bash
# Executado pelo Compose na imagem do Elasticsearch, como root, em duas etapas:
#   setup.sh certs   (serviço "certs", antes do es01)
#     1. Gera a CA e os certificados de es01 e kibana (somente na primeira vez).
#   setup.sh config  (serviço "setup", depois que o es01 está saudável)
#     2. Define a senha do kibana_system.
#     3. Cria o papel e o usuário do Logstash e o papel de leitura.
#     4. Aplica políticas ILM e templates de índice.
#   O certificado do syslog-relay (logs da firewall) é emitido pela mesma CA na etapa
#   certs, inclusive em instalações existentes que ainda não o têm.
# Idempotente: pode ser executado de novo após alterar templates.
set -euo pipefail

MODE="${1:-}"
case "$MODE" in
    certs|config) ;;
    *) echo "uso: setup.sh certs|config" >&2; exit 2 ;;
esac

CERTS=/usr/share/elasticsearch/config/certs
CA_DIR=/usr/share/elasticsearch/config/ca-private
SETUP=/setup
ES_URL=https://es01:9200
CA_CRT="$CERTS/ca/ca.crt"

if [[ "$MODE" == "certs" ]]; then
# 1. Certificados -----------------------------------------------------------------
# Extrai um .zip com unzip; sem ele (imagens mais enxutas), usa o jar do JDK embutido.
extract() {
    local zip=$1 dest=$2
    if command -v unzip >/dev/null; then
        unzip -q -o "$zip" -d "$dest"
    elif [[ -x /usr/share/elasticsearch/jdk/bin/jar ]]; then
        (cd "$dest" && /usr/share/elasticsearch/jdk/bin/jar xf "$zip")
    else
        echo "Nem unzip nem jar disponíveis para extrair $zip" >&2
        exit 1
    fi
}

if [[ ! -f "$CA_DIR/ca/ca.key" ]]; then
    if [[ -f "$CERTS/ca/ca.crt" || -f "$CERTS/es01/es01.crt" || -f /export/ca/ca.crt ]]; then
        echo "CA privada ausente com certificados existentes. Restaure ca_private; não será criada outra CA." >&2
        exit 1
    fi
    echo "Gerando CA"
    bin/elasticsearch-certutil ca --silent --pem -out "$CA_DIR/ca.zip"
    extract "$CA_DIR/ca.zip" "$CA_DIR"
    rm -f "$CA_DIR/ca.zip"
fi

extra_dns=""
extra_ip=""
[[ -n "${SOC_PUBLIC_DNS:-}" ]] && extra_dns=", ${SOC_PUBLIC_DNS}"
[[ -n "${SOC_PUBLIC_IP:-}" ]] && extra_ip=", ${SOC_PUBLIC_IP}"

if [[ ! -f "$CERTS/es01/es01.crt" && ! -f "$CERTS/kibana/kibana.crt" ]]; then
    echo "Gerando certificados"
    cat > "$CA_DIR/instances.yml" <<EOF
instances:
  - name: es01
    dns: [es01, localhost${extra_dns}]
    ip: [127.0.0.1${extra_ip}]
  - name: kibana
    dns: [kibana, localhost${extra_dns}]
    ip: [127.0.0.1${extra_ip}]
EOF
    bin/elasticsearch-certutil cert --silent --pem -out "$CA_DIR/certs.zip" \
        --in "$CA_DIR/instances.yml" --ca-cert "$CA_DIR/ca/ca.crt" --ca-key "$CA_DIR/ca/ca.key"
    extract "$CA_DIR/certs.zip" "$CERTS"
    rm -f "$CA_DIR/certs.zip"
    mkdir -p "$CERTS/ca"
    cp "$CA_DIR/ca/ca.crt" "$CERTS/ca/ca.crt"
fi

# Certificado do syslog-relay (TLS do FortiAnalyzer). Emitido à parte para não tocar nos
# certificados existentes; SAN com o IP/DNS pelo qual o FortiAnalyzer chega à VM.
if [[ ! -f "$CERTS/syslog/syslog.crt" ]]; then
    echo "Gerando certificado do syslog-relay"
    syslog_ip="${SOC_SYSLOG_IP:-${SOC_PUBLIC_IP:-}}"
    cat > "$CA_DIR/instances-syslog.yml" <<EOF
instances:
  - name: syslog
    dns: [syslog, syslog-relay${extra_dns}]
    ip: [127.0.0.1${syslog_ip:+, ${syslog_ip}}]
EOF
    bin/elasticsearch-certutil cert --silent --pem -out "$CA_DIR/syslog.zip" \
        --in "$CA_DIR/instances-syslog.yml" --ca-cert "$CA_DIR/ca/ca.crt" --ca-key "$CA_DIR/ca/ca.key"
    extract "$CA_DIR/syslog.zip" "$CERTS"
    rm -f "$CA_DIR/syslog.zip"
fi

# Nunca substituir silenciosamente um conjunto parcial nem trocar a confiança.
for f in ca/ca.crt es01/es01.crt es01/es01.key kibana/kibana.crt kibana/kibana.key syslog/syslog.crt syslog/syslog.key; do
    [[ -s "$CERTS/$f" ]] || { echo "Certificado/chave ausente: $f. Restaure o volume legado." >&2; exit 1; }
done
[[ "$(cat "$CA_DIR/ca/ca.crt")" == "$(cat "$CERTS/ca/ca.crt")" ]] || { echo "CA pública e privada divergentes; restaure o conjunto correto." >&2; exit 1; }

# A chave da CA fica só no volume do setup; os serviços (uid 1000) leem os certificados.
chown -R root:root "$CA_DIR"
chmod -R go-rwx "$CA_DIR"
chown -R 1000:0 "$CERTS"
find "$CERTS" -type d -exec chmod 750 {} \;
find "$CERTS" -type f -exec chmod 640 {} \;
chmod 644 "$CA_CRT"

# O volume legado só é montado neste gerador. Publica material mínimo por serviço,
# preservando exatamente a CA e os certificados existentes, inclusive na migração.
publish() {
    local source=$1 destination=$2 mode=$3
    install -o 1000 -g 0 -m "$mode" "$source" "${destination}.tmp"
    mv -f "${destination}.tmp" "$destination"
}
install -d -o 1000 -g 0 -m 755 /export/ca
install -d -o 1000 -g 0 -m 750 /export/es01 /export/kibana /export/syslog
publish "$CA_CRT" /export/ca/ca.crt 644
for service in es01 kibana syslog; do
    publish "$CERTS/$service/$service.crt" "/export/$service/$service.crt" 640
    publish "$CERTS/$service/$service.key" "/export/$service/$service.key" 640
done
echo "Certificados prontos"
exit 0
fi

# Etapa config ----------------------------------------------------------------------
: "${ELASTIC_PASSWORD:?defina ELASTIC_PASSWORD}"
: "${KIBANA_PASSWORD:?defina KIBANA_PASSWORD}"
: "${SOC_ES_LOGSTASH_USER:?defina SOC_ES_LOGSTASH_USER}"
: "${SOC_ES_LOGSTASH_PASSWORD:?defina SOC_ES_LOGSTASH_PASSWORD}"

for pw in "$ELASTIC_PASSWORD" "$KIBANA_PASSWORD" "$SOC_ES_LOGSTASH_PASSWORD"; do
    [[ "$pw" =~ ^[A-Za-z0-9_-]{16,}$ ]] || { echo "Senhas devem ter 16+ caracteres [A-Za-z0-9_-]." >&2; exit 1; }
done
[[ -f "$CA_CRT" ]] || { echo "CA não encontrada em $CA_CRT; o serviço certs rodou?" >&2; exit 1; }

# 2. Aguarda o Elasticsearch --------------------------------------------------------
# Credenciais vão por stdin (-K-) para não aparecerem na lista de processos.
es() {
    local method=$1 path=$2
    shift 2
    curl -sS --fail-with-body --cacert "$CA_CRT" -K- -X "$method" "${ES_URL}${path}" \
        -H 'Content-Type: application/json' "$@" <<<"user = \"elastic:${ELASTIC_PASSWORD}\""
}

echo "Aguardando o Elasticsearch"
for _ in $(seq 1 120); do
    if es GET /_cluster/health 2>/dev/null | grep -Eq '"status":"(green|yellow)"'; then
        break
    fi
    sleep 5
done
es GET /_cluster/health >/dev/null

# Corpos com senha ficam em arquivo temporário, não na linha de comando.
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
chmod 600 "$tmp"

echo "Definindo senha do kibana_system"
printf '{"password":"%s"}' "$KIBANA_PASSWORD" > "$tmp"
es POST /_security/user/kibana_system/_password --data-binary @"$tmp" >/dev/null

# 3. Papel e usuário do Logstash ------------------------------------------------------
echo "Configurando papel e usuário do Logstash"
cat > "$tmp" <<'EOF'
{
  "cluster": ["monitor"],
  "indices": [
    {
      "names": ["soc-*"],
      "privileges": ["create_index", "create", "index", "write", "view_index_metadata"]
    },
    {
      "names": ["fw-logs-*"],
      "privileges": ["create_index", "create_doc", "view_index_metadata"]
    }
  ]
}
EOF
es PUT /_security/role/soc_logstash_writer --data-binary @"$tmp" >/dev/null

printf '{"password":"%s","roles":["soc_logstash_writer"],"full_name":"Logstash SOC"}' "$SOC_ES_LOGSTASH_PASSWORD" > "$tmp"
es PUT "/_security/user/${SOC_ES_LOGSTASH_USER}" --data-binary @"$tmp" >/dev/null

# Leitura dos logs da firewall pelo coletor (agregados por hora). Opcional: sem a
# senha no .env, o usuário não é criado e a fonte fwflows fica desligada.
if [[ -n "${SOC_ES_COLLECTOR_PASSWORD:-}" ]]; then
    [[ "$SOC_ES_COLLECTOR_PASSWORD" =~ ^[A-Za-z0-9_-]{16,}$ ]] || { echo "Senhas devem ter 16+ caracteres [A-Za-z0-9_-]." >&2; exit 1; }
    echo "Configurando papel e usuário de leitura do coletor"
    echo '{"cluster":[],"indices":[{"names":["fw-logs-*"],"privileges":["read"]}]}' > "$tmp"
    es PUT /_security/role/soc_collector_fw_reader --data-binary @"$tmp" >/dev/null
    printf '{"password":"%s","roles":["soc_collector_fw_reader"],"full_name":"Coletor SOC (firewall)"}' "$SOC_ES_COLLECTOR_PASSWORD" > "$tmp"
    es PUT "/_security/user/${SOC_ES_COLLECTOR_USER:-soc_collector_es}" --data-binary @"$tmp" >/dev/null
fi

# Papéis humanos completos (índices + recursos por espaço) são geridos pelo
# kibana-setup via API Kibana. Não sobrescrever aqui as permissões de aplicações.

# 4. ILM e templates -----------------------------------------------------------------
for f in "$SETUP"/ilm/*.json; do
    name="$(basename "$f" .json)"
    echo "ILM: $name"
    es PUT "/_ilm/policy/${name}" --data-binary @"$f" >/dev/null
done

echo "Component template: soc-mappings"
MAPPINGS="$SETUP/mappings/soc-mappings.json"
{ printf '{"template":{"mappings":'; cat "$MAPPINGS"; printf '}}'; } > "$tmp"
es PUT /_component_template/soc-mappings --data-binary @"$tmp" >/dev/null

echo "Component template: soc-insights-mappings"
INSIGHTS_MAPPINGS="$SETUP/mappings/soc-insights-mappings.json"
{ printf '{"template":{"mappings":'; cat "$INSIGHTS_MAPPINGS"; printf '}}'; } > "$tmp"
es PUT /_component_template/soc-insights-mappings --data-binary @"$tmp" >/dev/null

echo "Component template: soc-windows-updates-mappings"
WINUPDATES_MAPPINGS="$SETUP/mappings/soc-windows-updates-mappings.json"
{ printf '{"template":{"mappings":'; cat "$WINUPDATES_MAPPINGS"; printf '}}'; } > "$tmp"
es PUT /_component_template/soc-windows-updates-mappings --data-binary @"$tmp" >/dev/null

echo "Component template: fw-logs-mappings"
FW_MAPPINGS="$SETUP/mappings/fw-logs-mappings.json"
{ printf '{"template":{"mappings":'; cat "$FW_MAPPINGS"; printf '}}'; } > "$tmp"
es PUT /_component_template/fw-logs-mappings --data-binary @"$tmp" >/dev/null

echo "Component template: soc-fw-flows-mappings"
FWFLOWS_MAPPINGS="$SETUP/mappings/soc-fw-flows-mappings.json"
{ printf '{"template":{"mappings":'; cat "$FWFLOWS_MAPPINGS"; printf '}}'; } > "$tmp"
es PUT /_component_template/soc-fw-flows-mappings --data-binary @"$tmp" >/dev/null

# Índices já existentes recebem os campos novos (somente inclusão; o ES recusa
# mudança de tipo). Documentos antigos só ganham os campos novos se republicados.
# soc-insights, soc-windows-updates* e soc-fw-flows-* têm mapeamento próprio e ficam de fora.
if es GET '/_cat/indices/soc-*,-soc-insights,-soc-windows-updates*,-soc-fw-flows-*?h=index' 2>/dev/null | grep -q .; then
    echo "Atualizando mapeamento dos índices soc-* existentes"
    es PUT '/soc-*,-soc-insights,-soc-windows-updates*,-soc-fw-flows-*/_mapping' --data-binary @"$MAPPINGS" >/dev/null
fi
if es GET '/_cat/indices/soc-fw-flows-*?h=index' 2>/dev/null | grep -q .; then
    echo "Atualizando mapeamento de soc-fw-flows-*"
    es PUT '/soc-fw-flows-*/_mapping' --data-binary @"$FWFLOWS_MAPPINGS" >/dev/null
fi
# Data stream: campos novos valem para o índice de escrita atual; os próximos usam o template.
if es GET '/_data_stream/fw-logs-fortigate' >/dev/null 2>&1; then
    echo "Atualizando mapeamento de fw-logs-fortigate"
    es PUT '/fw-logs-fortigate/_mapping' --data-binary @"$FW_MAPPINGS" >/dev/null
fi
if es GET '/_cat/indices/soc-windows-updates*?h=index' 2>/dev/null | grep -q .; then
    echo "Atualizando mapeamento de soc-windows-updates*"
    es PUT '/soc-windows-updates*/_mapping' --data-binary @"$WINUPDATES_MAPPINGS" >/dev/null
fi
if es GET '/_cat/indices/soc-insights?h=index' 2>/dev/null | grep -q .; then
    echo "Atualizando mapeamento de soc-insights"
    es PUT '/soc-insights/_mapping' --data-binary @"$INSIGHTS_MAPPINGS" >/dev/null
fi

for f in "$SETUP"/templates/index-*.json; do
    name="$(basename "$f" .json | sed 's/^index-//')"
    echo "Index template: $name"
    es PUT "/_index_template/${name}" --data-binary @"$f" >/dev/null
done

# soc-insights é estado atual (um índice, sem data no nome). Criado vazio para o
# data view e o dashboard terem os campos antes do primeiro cálculo de insights.
if ! es GET '/_cat/indices/soc-insights?h=index' 2>/dev/null | grep -q .; then
    echo "Criando índice vazio soc-insights"
    es PUT /soc-insights >/dev/null
fi
if ! es GET '/_cat/indices/soc-windows-updates?h=index' 2>/dev/null | grep -q .; then
    echo "Criando índice vazio soc-windows-updates"
    es PUT /soc-windows-updates >/dev/null
fi

echo "Setup concluído"
