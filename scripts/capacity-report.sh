#!/usr/bin/env bash
# Relatório manual somente de leitura para executar na VM correspondente.
set -euo pipefail
mode="${1:-docker}"
case "$mode" in
  docker|postgres) ;;
  *) echo 'Uso: bash scripts/capacity-report.sh docker|postgres' >&2; exit 2 ;;
esac
date -u '+%Y-%m-%dT%H:%M:%SZ'
printf '\nMemória da VM\n'
free -h
printf '\nDiscos\n'
df -h
if [[ "$mode" == docker ]]; then
  printf '\nContainers (amostra atual, não média histórica)\n'
  docker stats --no-stream --format 'table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}\t{{.BlockIO}}'
else
  printf '\nTamanho do banco SOC\n'
  sudo -u postgres psql -X -v ON_ERROR_STOP=1 -d soc -c \
    "SELECT now() AT TIME ZONE 'UTC' AS collected_utc, pg_size_pretty(pg_database_size(current_database())) AS database_size;"
fi
