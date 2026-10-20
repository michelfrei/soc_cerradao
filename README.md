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
| `docker/` | `compose.yml`, `.env.example`, segredos e preparação da VM do Docker |
| `scripts/` | Validação local com Docker Desktop |
| `docs/` | [Runbook](docs/RUNBOOK.md) e [decisões técnicas](docs/DECISOES.md) |

## Situação

Fase 1 do piloto: fundação e indexação.

- Incidentes e alertas habilitados por padrão.
- `DeviceLogonEvents` e eventos ASR já implementados, mas desabilitados até a
  validação da primeira coleta (ver runbook, seção 7).
- Ainda não incluídos: regras de detecção, painéis, Grafana, backup automatizado,
  CI e frentes de movimentação lateral e IA.

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
