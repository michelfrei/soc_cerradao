<#
.SYNOPSIS
  Validação local do projeto SOC com Docker Desktop (não acessa Microsoft nem as VMs).

.DESCRIPTION
  1. Sobe um PostgreSQL 18 temporário e aplica bootstrap.sql e as migrações.
  2. Instala dependências do coletor, gera o package-lock.json, checa tipos e roda
     os testes unitários e de integração (inclui o teste de ordem de commit).
  3. Valida o docker compose (com valores fictícios), a sintaxe do pipeline do
     Logstash e os scripts shell (bash -n e shellcheck).
  Tudo é removido ao final, exceto o package-lock.json gerado.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\validate.ps1
#>
param(
    [string]$StackVersion = '9.5.5',
    [string]$NodeImage = 'node:24-bookworm-slim',
    [string]$PostgresImage = 'postgres:18'
)

# 'Continue': no PowerShell 5.1, 'Stop' transforma qualquer saída em stderr do docker
# (ex.: progresso de download) em erro. As falhas são checadas por $LASTEXITCODE.
$ErrorActionPreference = 'Continue'
# SQL com acentos enviado por pipe ao docker precisa sair em UTF-8 (Windows PowerShell 5.1).
$OutputEncoding = New-Object System.Text.UTF8Encoding $false
$root = Split-Path -Parent $PSScriptRoot
$net = 'soc-validate'
$pg = 'soc-validate-pg'
$results = [ordered]@{}

function Invoke-Step([string]$name, [scriptblock]$block) {
    Write-Host "`n=== $name ===" -ForegroundColor Cyan
    $global:LASTEXITCODE = 0
    try {
        & $block
        if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) { throw "código de saída $LASTEXITCODE" }
        $results[$name] = 'APROVADO'
    } catch {
        $results[$name] = "REPROVADO: $($_.Exception.Message)"
        Write-Host $results[$name] -ForegroundColor Red
    }
}

function New-Secret { -join ((1..32) | ForEach-Object { '{0:x}' -f (Get-Random -Maximum 16) }) }

$pgSuper = New-Secret
$collectorPw = New-Secret
$logstashPw = New-Secret

try {
    docker network create $net | Out-Null

    Invoke-Step 'PostgreSQL: bootstrap e migrações' {
        docker run -d --name $pg --network $net -e POSTGRES_PASSWORD=$pgSuper $PostgresImage | Out-Null
        $ready = $false
        for ($i = 0; $i -lt 60; $i++) {
            docker exec $pg pg_isready -U postgres -q 2>$null
            if ($LASTEXITCODE -eq 0) { $ready = $true; break }
            Start-Sleep 1
        }
        if (-not $ready) { throw 'PostgreSQL não ficou pronto' }
        Start-Sleep 2
        Get-Content -Raw "$root\postgres\bootstrap.sql" |
            docker exec -i -e SOC_COLLECTOR_PASSWORD=$collectorPw -e SOC_LOGSTASH_PASSWORD=$logstashPw $pg `
                psql -X -q -v ON_ERROR_STOP=1 -U postgres -d postgres -f -
        if ($LASTEXITCODE -ne 0) { throw 'bootstrap.sql falhou' }
        # Segunda execução: precisa ser idempotente.
        Get-Content -Raw "$root\postgres\bootstrap.sql" |
            docker exec -i -e SOC_COLLECTOR_PASSWORD=$collectorPw -e SOC_LOGSTASH_PASSWORD=$logstashPw $pg `
                psql -X -q -v ON_ERROR_STOP=1 -U postgres -d postgres -f -
        if ($LASTEXITCODE -ne 0) { throw 'bootstrap.sql não é idempotente' }
        foreach ($f in Get-ChildItem "$root\postgres\migrations\*.sql" | Sort-Object Name) {
            $v = $f.BaseName
            Write-Host "migração $v"
            Get-Content -Raw $f.FullName |
                docker exec -i $pg psql -X -q -v ON_ERROR_STOP=1 -U postgres -d soc --single-transaction `
                    -c 'SET ROLE soc_owner' -f - -c "INSERT INTO soc.schema_migrations (version) VALUES ('$v')"
            if ($LASTEXITCODE -ne 0) { throw "migração $v falhou" }
        }
        # Rotinas de manutenção: o procedimento precisa conseguir confirmar fatias (COMMIT).
        docker exec $pg psql -X -q -v ON_ERROR_STOP=1 -U postgres -d soc `
            -c "CALL soc.republish_events('DeviceLogonEvents', now() - interval '3 days', now())" `
            -c "SELECT soc.purge_publication(0)" -c "SELECT soc.republish_objects('incident')"
        if ($LASTEXITCODE -ne 0) { throw 'rotinas de manutenção falharam' }
    }

    Invoke-Step 'Coletor: dependências, tipos e testes' {
        docker run --rm --network $net `
            -v "${root}\collector:/app" -v soc-validate-node-modules:/app/node_modules -w /app `
            -e SOC_TEST_PG_HOST=$pg -e SOC_TEST_COLLECTOR_PASSWORD=$collectorPw -e SOC_TEST_LOGSTASH_PASSWORD=$logstashPw `
            $NodeImage sh -c 'npm install --no-audit --no-fund && npm run typecheck && npm test && npm run build'
    }

    Invoke-Step 'Docker Compose: configuração' {
        $envFile = Join-Path $env:TEMP 'soc-validate.env'
        @"
STACK_VERSION=$StackVersion
KIBANA_PUBLIC_URL=https://soc.example.local:5601
SOC_PG_HOST=10.0.0.10
SOC_LOGSTASH_DB_PASSWORD=x
ELASTIC_PASSWORD=x
KIBANA_PASSWORD=x
SOC_ES_LOGSTASH_PASSWORD=x
KIBANA_ENCRYPTION_KEY=x
KIBANA_SECURITY_KEY=x
KIBANA_REPORTING_KEY=x
GRAPH_TENANT_ID=00000000-0000-0000-0000-000000000000
GRAPH_CLIENT_ID=00000000-0000-0000-0000-000000000000
"@ | Set-Content -Encoding ascii $envFile
        $secrets = "$root\docker\secrets"
        $created = @()
        foreach ($s in 'graph_client_secret', 'pg_collector_password') {
            if (-not (Test-Path "$secrets\$s")) { Set-Content "$secrets\$s" 'x'; $created += "$secrets\$s" }
        }
        try {
            docker compose -f "$root\docker\compose.yml" --env-file $envFile config -q
        } finally {
            $created | ForEach-Object { Remove-Item $_ -Force }
            Remove-Item $envFile -Force
        }
    }

    Invoke-Step 'Logstash: sintaxe do pipeline' {
        # O teste só confere se o caminho da CA existe; um arquivo fictício basta.
        $fakeCerts = Join-Path $env:TEMP 'soc-validate-certs'
        New-Item -ItemType Directory -Force "$fakeCerts\ca" | Out-Null
        Set-Content "$fakeCerts\ca\ca.crt" 'placeholder'
        docker run --rm `
            -v "${fakeCerts}:/usr/share/logstash/certs:ro" `
            -v "${root}\logstash\pipeline:/usr/share/logstash/pipeline:ro" `
            -v "${root}\logstash\sql:/usr/share/logstash/sql:ro" `
            -e SOC_PG_HOST=x -e SOC_PG_PORT=5432 -e SOC_PG_SSLMODE=require `
            -e SOC_LOGSTASH_DB_USER=x -e SOC_LOGSTASH_DB_PASSWORD=x `
            -e SOC_ES_HOSTS=https://es01:9200 -e SOC_ES_LOGSTASH_USER=x -e SOC_ES_LOGSTASH_PASSWORD=x `
            "docker.elastic.co/logstash/logstash:$StackVersion" `
            bin/logstash --config.test_and_exit -f /usr/share/logstash/pipeline/soc-publication.conf
    }

    Invoke-Step 'Scripts shell: sintaxe e shellcheck' {
        docker run --rm -v "${root}:/src:ro" -w /src koalaman/shellcheck:v0.10.0 `
            -S warning postgres/setup-postgres.sh postgres/migrate.sh elasticsearch/setup.sh docker/host/prepare-docker-host.sh kibana/setup.sh
    }

    Invoke-Step 'Kibana: pacote de dashboards e regras atualizado' {
        # Falha se kibana/dist não corresponder a kibana/build.mjs e kibana/rules.
        docker run --rm -v "${root}:/repo:ro" -w /repo $NodeImage node kibana/build.mjs --check
    }
}
finally {
    docker rm -f $pg 2>$null | Out-Null
    docker network rm $net 2>$null | Out-Null
    docker volume rm soc-validate-node-modules 2>$null | Out-Null
}

Write-Host "`n=== Resultado ===" -ForegroundColor Cyan
$results.GetEnumerator() | ForEach-Object { '{0,-45} {1}' -f $_.Key, $_.Value }
if ($results.Values | Where-Object { $_ -ne 'APROVADO' }) { exit 1 }
