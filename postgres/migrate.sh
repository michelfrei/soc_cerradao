#!/usr/bin/env bash
# Aplica as migrações pendentes de postgres/migrations no banco "soc".
# Uso (na VM do PostgreSQL): sudo ./postgres/migrate.sh
# Cada arquivo roda em transação única, como soc_owner, e é registrado em
# soc.schema_migrations. Arquivos já aplicados são ignorados.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DB="${SOC_DB:-soc}"

if [[ $EUID -ne 0 ]]; then
    echo "Execute com sudo." >&2
    exit 1
fi

psql_pg() {
    sudo -u postgres psql -X -q -v ON_ERROR_STOP=1 -d "$DB" "$@"
}

shopt -s nullglob
files=("$DIR"/migrations/*.sql)
if [[ ${#files[@]} -eq 0 ]]; then
    echo "Nenhuma migração encontrada em $DIR/migrations." >&2
    exit 1
fi

applied=0
for f in "${files[@]}"; do
    version="$(basename "$f" .sql)"
    if [[ ! "$version" =~ ^[0-9]{3}_[a-z0-9_]+$ ]]; then
        echo "Nome de migração inválido: $version" >&2
        exit 1
    fi
    exists="$(psql_pg -tA -c "SELECT 1 FROM soc.schema_migrations WHERE version = '$version'")"
    if [[ "$exists" == "1" ]]; then
        continue
    fi
    echo "Aplicando $version"
    # O arquivo vai por stdin: o usuário postgres pode não ter acesso à pasta do repositório.
    psql_pg --single-transaction \
        -c "SET ROLE soc_owner" \
        -f - \
        -c "INSERT INTO soc.schema_migrations (version) VALUES ('$version')" < "$f"
    applied=$((applied + 1))
done

echo "Migrações aplicadas nesta execução: $applied"
