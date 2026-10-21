# SOC — monitoramento de acessos e detecção de ameaças

Microsoft Defender XDR → Microsoft Graph Security API → coletor Node.js/TypeScript →
PostgreSQL → Logstash → Elasticsearch / Kibana (Elastic Security).

## Estrutura

| Pasta | Conteúdo |
|---|---|
| `collector/` | Coletor TypeScript: incidentes, alertas e Advanced Hunting (KQL em `queries/`, fontes em `config/sources.json`) |
| `postgres/` | Preparação da VM do PostgreSQL 18, papéis e migrações versionadas |
| `logstash/` | Imagem com driver JDBC, pipeline e consulta incremental |
| `elasticsearch/` | Setup de certificados, usuários, ILM e templates de índice |
| `kibana/` | Dashboards e data views (`build.mjs`), regras de detecção (`rules/`) e importação (`setup.sh`) |
| `docker/` | `compose.yml`, `.env.example`, segredos e preparação da VM do Docker |
| `scripts/` | Validação local com Docker Desktop; `lab/` com dados sintéticos para laboratório |
| `docs/` | [Runbook](docs/RUNBOOK.md), [decisões técnicas](docs/DECISOES.md) e [detecções](docs/DETECCOES.md) |

## Situação

- Coleta: incidentes, alertas, `DeviceLogonEvents` (servidores) e ASR, com reconciliação de 24 h.
- Kibana: dashboards de visão geral, acessos/movimentação e ASR; 8 regras de detecção
  em modo observação (frentes 1, 3 e 4).
- Ainda não incluídos: backup automatizado, Grafana, CI, `DeviceProcessEvents` /
  `DeviceNetworkEvents` e a frente de IA.

## Validação local

Requer Docker Desktop:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\validate.ps1
```

Sobe um PostgreSQL 18 temporário, aplica as migrações, roda os testes do coletor
(inclusive os de integração com o banco), valida o Compose, o pipeline do Logstash
e os scripts shell. Também gera o `collector/package-lock.json`, que deve ser versionado.

Desenvolvimento do coletor com Node 24 instalado:

```powershell
cd collector
npm install
npm run typecheck
npm test
```
