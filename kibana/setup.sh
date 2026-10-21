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
SPACE=soc

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

# Espaço explícito: o espaço default e suas regras/objetos antigos são preservados.
echo "Preparando espaço SOC e papéis"
if ! kb GET "/api/spaces/space/$SPACE" >/dev/null 2>&1; then
    kb POST /api/spaces/space -H 'Content-Type: application/json' \
        --data-binary '{"id":"soc","name":"SOC","description":"Monitoramento e investigacao SOC","disabledFeatures":[]}' >/dev/null
fi

# IDs verificados no código oficial Kibana v9.5.5; não ampliar privilégios como
# fallback se outra versão não disponibilizar algum dos recursos necessários.
features="$(kb GET /api/features)"
for feature in dashboard_v2 discover_v2 visualize_v2 siemV5 securitySolutionRulesV4 securitySolutionAlertsV1 securitySolutionCasesV3 indexPatterns advancedSettings savedObjectsManagement savedQueryManagement; do
    if ! grep -Eq '"id"[[:space:]]*:[[:space:]]*"'"$feature"'"' <<<"$features"; then
        echo "Recurso Kibana ausente: $feature. Verifique a versao da stack antes de aplicar papeis." >&2
        exit 1
    fi
done
for role in /kibana/roles/*.json; do
    name="$(basename "$role" .json)"
    kb PUT "/api/security/role/$name" -H 'Content-Type: application/json' --data-binary @"$role" >/dev/null
done

# APIs de objetos, configurações e detecções respeitam o namespace do espaço.
soc() {
    local method=$1 path=$2
    shift 2
    kb "$method" "/s/$SPACE$path" "$@"
}

# 1. Objetos salvos ---------------------------------------------------------------
echo "Importando data views e dashboards"
out="$(soc POST '/api/saved_objects/_import?overwrite=true' -F "file=@${DIST}/objects.ndjson")"
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
soc POST /api/kibana/settings -H 'Content-Type: application/json' -H 'x-elastic-internal-origin: kibana' \
    --data-binary @"$body" >/dev/null

# 3. Regras de detecção -------------------------------------------------------------
if [[ -s "${DIST}/rules.ndjson" ]]; then
    echo "Importando regras de detecção"
    out="$(soc POST '/api/detection_engine/rules/_import?overwrite=true' -F "file=@${DIST}/rules.ndjson")"
    if ! grep -q '"success":true' <<<"$out"; then
        echo "Falha na importação das regras: $out" >&2
        exit 1
    fi
    echo "  $(grep -o '"success_count":[0-9]*' <<<"$out")"
fi

echo "Kibana configurado no espaço SOC (/s/soc). Use usuarios nominais; elastic somente bootstrap."
