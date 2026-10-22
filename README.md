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

- Coleta: incidentes, alertas, `DeviceLogonEvents`, ASR, `DeviceProcessEvents`,
  `DeviceNetworkEvents` e inventário horário `DeviceInfo`;
  eventos com reconciliação de 24 h. Nomes incluem `srv`/`fisico` e excluem
  `note`/`micro`, ignorando maiúsculas; exclusões prevalecem.
- Identidades: contas qualificadas por domínio/servidor, SID e catálogo opcional
  de classificação. [Contrato de identidades](docs/IDENTIDADES.md).
- Postura: snapshots TVM de vulnerabilidades e avaliações de configuração a cada
  seis horas; estado atual separado dos eventos, sem apagar resultados por falha.
- Kibana: espaço `soc`, sete dashboards, oito regras v2 em observação e perfis
  observer/analyst/admin. [Guia das telas](docs/DASHBOARDS.md).
- Capacidade: snapshots PostgreSQL/Elasticsearch; relatório manual da VM em
  `bash scripts/capacity-report.sh docker` ou `postgres`.
- Ainda não incluídos: backup automatizado, Grafana, CI, exportação detalhada da
  saúde do antivírus pela API MDE e a frente de IA.

**Próxima atualização (processos, rede e postura):** siga
[DEPLOY-PROCESSOS-EXPOSICAO.md](docs/DEPLOY-PROCESSOS-EXPOSICAO.md), com migração 004
no PostgreSQL antes de ativar o coletor 0.3.0 e os novos dashboards.

**Evolução anterior (identidades/cobertura):** [DEPLOY-EVOLUCAO.md](docs/DEPLOY-EVOLUCAO.md).
Aplica primeiro a migração 003 no PostgreSQL 18, depois atualiza a VM-Docker.
O guia inclui isolamento de certificados sem trocar a CA, ativação opcional de
`verify-full`, transição do espaço default para SOC e reautorização das regras.
O [runbook inicial](docs/RUNBOOK.md) continua como referência de preparação das VMs.

Inventário esperado opcional: `collector/config/assets.json` (vazio por padrão);
classificação de contas: `logstash/config/identities.json`. Esses cadastros não
restringem quais servidores dentro do filtro de nomes são coletados.

## Validação local

Requer Docker Desktop:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\validate.ps1
```

Sobe um PostgreSQL 18 temporário, aplica as migrações, roda os testes do coletor
(inclusive os de integração com o banco), valida o Compose, o pipeline do Logstash
e os scripts shell. Usa o `collector/package-lock.json` versionado.

Integração opcional com Elasticsearch/Kibana 9.5.5 locais, dados sintéticos e
PostgreSQL temporário com TLS (não inicia Graph/coletor, não usa `.env` real):

```powershell
node scripts/lab/smoke-evolution.mjs
```

O teste usa as portas locais 15601/19200; elas precisam estar livres. Os recursos
possuem nomes exclusivos e são removidos ao final. Não aponta para as VMs reais.

Desenvolvimento do coletor com Node 24 instalado:

```powershell
cd collector
npm install
npm run typecheck
npm test
``````
