#!/usr/bin/env bash
# Executado pelo serviço "kibana-setup" do Compose depois que o Kibana fica saudável.
#  1. Importa data views, visualizações e dashboards (dist/objects.ndjson).
#  2. Inclui soc-events-* nos índices padrão do Elastic Security.
#  3. Importa as regras de detecção (dist/rules.ndjson), sem notificações.
# Idempotente: sobrescreve os objetos com os mesmos ids.
set -euo pipefail

: "${ELASTIC_PASSWORD:?defina ELASTIC_PASSWORD}"
KB_URL="${KB_URL:-https://kibana:5601}"
CA_CRT=/usr/share/elasticsearch/config/certs/ca/ca.crt
DIST=/kibana/dist

# Credenciais por stdin (-K-), fora da lista de processos.
kb() {
    local method=$1 path=$2
    shift 2
    curl -sS --fail-with-body --cacert "$CA_CRT" -K- -X "$method" "${KB_URL}${path}" \
        -H 'kbn-xsrf: soc-setup' -H 'elastic-api-version: 2023-10-31' "$@" \
        <<<"user = \"elastic:${ELASTIC_PASSWORD}\""
}

echo "Aguardando o Kibana"
for _ in $(seq 1 120); do
    if kb GET /api/status 2>/dev/null | grep -q '"level":"available"'; then
        break
    fi
    sleep 5
done
kb GET /api/status >/dev/null

# 1. Objetos salvos ---------------------------------------------------------------
echo "Importando data views e dashboards"
out="$(kb POST '/api/saved_objects/_import?overwrite=true' -F "file=@${DIST}/objects.ndjson")"
if ! grep -q '"success":true' <<<"$out"; then
    echo "Falha na importação dos objetos: $out" >&2
    exit 1
fi
echo "  $(grep -o '"successCount":[0-9]*' <<<"$out")"

# 2. Índices do Elastic Security ---------------------------------------------------
# Padrões de fábrica do Security mais os índices do SOC.
echo "Configurando índices do Elastic Security"
# O stdin do curl já leva as credenciais; o corpo vai por arquivo temporário.
body="$(mktemp)"
trap 'rm -f "$body"' EXIT
cat > "$body" <<'EOF'
{"changes":{"securitySolution:defaultIndex":[
  "soc-events-*",
  "apm-*-transaction*","auditbeat-*","endgame-*","filebeat-*","logs-*",
  "packetbeat-*","traces-apm*","winlogbeat-*","-*elastic-cloud-logs-*"
]}}
EOF
# Endpoint interno do Kibana: exige o cabeçalho de origem interna.
kb POST /api/kibana/settings -H 'Content-Type: application/json' -H 'x-elastic-internal-origin: kibana' \
    --data-binary @"$body" >/dev/null

# 3. Regras de detecção -------------------------------------------------------------
if [[ -s "${DIST}/rules.ndjson" ]]; then
    echo "Importando regras de detecção"
    out="$(kb POST '/api/detection_engine/rules/_import?overwrite=true' -F "file=@${DIST}/rules.ndjson")"
    if ! grep -q '"success":true' <<<"$out"; then
        echo "Falha na importação das regras: $out" >&2
        exit 1
    fi
    echo "  $(grep -o '"success_count":[0-9]*' <<<"$out")"
fi

echo "Kibana configurado"
