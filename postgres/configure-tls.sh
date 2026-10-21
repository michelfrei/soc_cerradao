#!/usr/bin/env bash
# Ubuntu 26.04 / PostgreSQL 18. Execucao MANUAL; nao executado pelo setup/Compose.
# Prepara certificado com SAN; APPLY_TLS=1 instala conf.d/20-soc-tls.conf.
# PG_TLS_DNS e PG_TLS_IPS: listas separadas por virgula, ao menos uma obrigatoria.
# A CA privada permanece fora do repositorio e NUNCA e substituida automaticamente.
set -euo pipefail
umask 077
die() { echo "ERRO: $*" >&2; exit 1; }
[[ $EUID -eq 0 ]] || die "execute com sudo."
command -v openssl >/dev/null || die "openssl nao encontrado."
command -v realpath >/dev/null || die "realpath nao encontrado."
PG_VERSION="${PG_VERSION:-18}"
PG_CLUSTER="${PG_CLUSTER:-main}"
[[ "$PG_VERSION" == 18 && "$PG_CLUSTER" =~ ^[a-zA-Z0-9_-]+$ ]] || die "destino suportado: PostgreSQL 18, nome de cluster simples."
CONF_DIR="/etc/postgresql/$PG_VERSION/$PG_CLUSTER"
[[ -d "$CONF_DIR/conf.d" ]] || die "cluster/conf.d nao encontrado."
CA_DIR="$(realpath -m "${PG_TLS_CA_DIR:-/root/soc-pg-ca}")"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ "$CA_DIR" != "$REPO" && "$CA_DIR" != "$REPO/"* ]] || die "CA privada deve ficar fora do repositorio."
case "$CA_DIR" in
    /|/root|/etc|/etc/ssl|/etc/postgresql|/var|/var/lib|/usr|/home)
        die "PG_TLS_CA_DIR deve ser uma pasta dedicada a esta CA, nao uma pasta geral do sistema." ;;
esac
TLS_DIR="$CONF_DIR/soc-tls"
TLS_CONF="$CONF_DIR/conf.d/20-soc-tls.conf"
DAYS="${PG_TLS_DAYS:-397}"
[[ "$DAYS" =~ ^[0-9]+$ && "$DAYS" -ge 1 && "$DAYS" -le 825 ]] || die "PG_TLS_DAYS deve estar entre 1 e 825."
[[ -n "${PG_TLS_DNS:-}${PG_TLS_IPS:-}" ]] || die "informe PG_TLS_DNS e/ou PG_TLS_IPS com os nomes/IPs reais usados pelos clientes."
tmp="$(mktemp -d)"
trap 'rm -rf -- "$tmp"' EXIT
dns_names=()
ip_addresses=()
IFS=',' read -r -a dns_names <<<"${PG_TLS_DNS:-}"
IFS=',' read -r -a ip_addresses <<<"${PG_TLS_IPS:-}"
san=""
cn=""
for dns in "${dns_names[@]}"; do
    [[ "$dns" =~ ^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$ && ${#dns} -le 253 && "$dns" != *..* ]] || die "DNS invalido: use nomes sem espacos, wildcard ou caracteres de configuracao."
    IFS='.' read -r -a labels <<<"$dns"
    for label in "${labels[@]}"; do
        [[ ${#label} -le 63 && "$label" != -* && "$label" != *- ]] || die "rotulo DNS invalido."
    done
    san+="${san:+,}DNS:$dns"
    [[ -n "$cn" ]] || cn="$dns"
done
for address in "${ip_addresses[@]}"; do
    [[ "$address" =~ ^[0-9a-fA-F:.]+$ ]] || die "IP invalido."
    # OpenSSL tambem valida a sintaxe IPv4/IPv6 ao criar o CSR abaixo.
    san+="${san:+,}IP:$address"
    [[ -n "$cn" ]] || cn="$address"
done
[[ -n "$san" ]] || die "lista de SAN vazia."
# CN nao autentica o host: clientes verify-full usam os SAN explicitamente.
cn="${cn:0:64}"
printf '%s\n' "$san" > "$tmp/san"
openssl req -new -newkey rsa:3072 -nodes -keyout "$tmp/server.key" -out "$tmp/server.csr" \
    -subj "/CN=$cn" -addext "subjectAltName=$san" >/dev/null 2>&1 || die "SAN/CSR invalido; nenhum certificado instalado."

install -d -o root -g root -m 700 "$CA_DIR"
if [[ ! -e "$CA_DIR/ca.key" && ! -e "$CA_DIR/ca.crt" ]]; then
    if [[ -e "$TLS_DIR/server.crt" || -e "$TLS_DIR/ca.crt" ]]; then
        die "Certificados existentes sem a CA original. Restaure a CA; a confianca nao sera substituida."
    fi
    openssl req -x509 -newkey rsa:4096 -nodes -sha256 -days 3650 \
        -keyout "$tmp/ca.key" -out "$tmp/ca.crt" -subj '/CN=SOC PostgreSQL CA' \
        -addext 'basicConstraints=critical,CA:TRUE' \
        -addext 'keyUsage=critical,keyCertSign,cRLSign' >/dev/null 2>&1
    install -o root -g root -m 600 "$tmp/ca.key" "$CA_DIR/ca.key"
    install -o root -g root -m 644 "$tmp/ca.crt" "$CA_DIR/ca.crt"
elif [[ ! -s "$CA_DIR/ca.key" || ! -s "$CA_DIR/ca.crt" ]]; then
    die "CA parcial. Restaure o par existente; uma CA nova nao sera gerada."
fi
chmod 700 "$CA_DIR"
chown root:root "$CA_DIR/ca.key" "$CA_DIR/ca.crt"
chmod 600 "$CA_DIR/ca.key"
openssl x509 -in "$CA_DIR/ca.crt" -checkend "$((DAYS * 86400))" -noout >/dev/null || die "CA vence antes do novo certificado. Planeje rotacao de confianca separadamente."
openssl pkey -in "$CA_DIR/ca.key" -pubout > "$tmp/ca-key.pub"
openssl x509 -in "$CA_DIR/ca.crt" -pubkey -noout > "$tmp/ca-cert.pub"
cmp -s "$tmp/ca-key.pub" "$tmp/ca-cert.pub" || die "chave privada nao corresponde a CA existente."

renew=1
if [[ -s "$TLS_DIR/server.crt" && -s "$TLS_DIR/server.key" && "${PG_TLS_RENEW:-0}" != 1 ]]; then
    cmp -s "$tmp/san" "$TLS_DIR/san.txt" || die "SAN mudou; revise clientes e use PG_TLS_RENEW=1 para renovar com a mesma CA."
    if openssl verify -CAfile "$CA_DIR/ca.crt" "$TLS_DIR/server.crt" >/dev/null 2>&1 && \
        openssl x509 -in "$TLS_DIR/server.crt" -checkend 2592000 -noout >/dev/null; then
        renew=0
    fi
fi
if [[ "$renew" == 1 ]]; then
    cat > "$tmp/extensions" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=$san
EOF
    # Serial aleatorio: renovar nao depende de arquivo global .srl nem troca a CA.
    openssl x509 -req -in "$tmp/server.csr" -CA "$CA_DIR/ca.crt" -CAkey "$CA_DIR/ca.key" \
        -set_serial "0x$(openssl rand -hex 16)" -days "$DAYS" -sha256 \
        -extfile "$tmp/extensions" -out "$tmp/server.crt" >/dev/null 2>&1
    openssl verify -CAfile "$CA_DIR/ca.crt" "$tmp/server.crt" >/dev/null
    for dns in "${dns_names[@]}"; do openssl x509 -in "$tmp/server.crt" -checkhost "$dns" -noout >/dev/null || die "SAN DNS nao confere."; done
    for address in "${ip_addresses[@]}"; do openssl x509 -in "$tmp/server.crt" -checkip "$address" -noout >/dev/null || die "SAN IP nao confere."; done
    if [[ -d "$TLS_DIR" ]]; then
        backup="/var/backups/soc-postgres/tls-$(date -u +%Y%m%dT%H%M%SZ)-$$"
        install -d -o root -g root -m 700 "$backup"
        cp -a "$TLS_DIR" "$backup/"
        [[ ! -f "$TLS_CONF" ]] || cp -a "$TLS_CONF" "$backup/"
        echo "Conjunto anterior preservado em $backup"
    fi
    install -d -o root -g postgres -m 750 "$TLS_DIR"
    install -o root -g postgres -m 640 "$tmp/server.key" "$TLS_DIR/server.key"
    install -o root -g postgres -m 644 "$tmp/server.crt" "$TLS_DIR/server.crt"
    install -o root -g postgres -m 644 "$CA_DIR/ca.crt" "$TLS_DIR/ca.crt"
    install -o root -g postgres -m 644 "$tmp/san" "$TLS_DIR/san.txt"
    echo "Certificado emitido/renovado com a mesma CA."
else
    echo "Certificado existente valido por mais de 30 dias; preservado."
fi

if [[ "${APPLY_TLS:-0}" == 1 ]]; then
    # Nao substituir uma PKI corporativa preexistente por suposicao.
    current="$(sudo -u postgres psql -X -Atq -p "${PGPORT:-5432}" -d postgres -c 'SHOW ssl_cert_file')"
    [[ "$current" == "$TLS_DIR/server.crt" || "$current" == /etc/ssl/certs/ssl-cert-snakeoil.pem ]] || \
        die "Certificado ativo personalizado ($current). Integre a PKI existente manualmente; configuracao ativa preservada."
    cat > "$tmp/20-soc-tls.conf" <<EOF
# Gerido por postgres/configure-tls.sh. CA privada fora do repositorio.
ssl = on
ssl_cert_file = '$TLS_DIR/server.crt'
ssl_key_file = '$TLS_DIR/server.key'
EOF
    install -o postgres -g postgres -m 644 "$tmp/20-soc-tls.conf" "$TLS_CONF"
    echo "Configuracao instalada. Aplique em janela planejada: sudo systemctl reload postgresql@$PG_VERSION-$PG_CLUSTER"
fi
echo "CA PUBLICA a copiar para docker/certs/postgres/ca.crt: $CA_DIR/ca.crt"
echo "Nunca copie $CA_DIR/ca.key nem $TLS_DIR/server.key para a VM-Docker."
echo "Ative verify-full apenas apos instalar a CA publica e validar SOC_PG_HOST contra o SAN."
