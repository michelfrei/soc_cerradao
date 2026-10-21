# Plano de evolução do piloto SOC

- ID: SOC-identidades-cobertura
- Versão: 1
- Criado em: 2026-10-21 (America/Sao_Paulo)
- Projeto: `C:\dev\soc`; duas VMs Ubuntu 26.04, PostgreSQL 18 nativo e Docker/Elastic.
- Estado: CONCLUÍDA a implementação local; deploy e conferência visual na implantação pendentes do responsável.

## Objetivo e critérios de sucesso

Preservar a coleta de nomes contendo `srv` ou `fisico`, sempre excluindo `note` ou
`micro`, sem diferenciar maiúsculas. Identificar contas sem misturar domínios ou
contas locais, enriquecer inventário, entregar cinco dashboards, perfis Kibana,
isolamento de certificados e métricas de capacidade com instruções de deploy.

## Escopo e autorização

Autorização: solicitação de implementação local do usuário nesta conversa.
Somente arquivos locais e validação em containers temporários. O deploy nas VMs
será feito pelo usuário. Não acessar Graph real nem credenciais de implantação.
Backup/restauração, quarentena de rejeições e garantias de atraso/durabilidade
ficam fora desta rodada, por decisão expressa do usuário.

## Tarefas

| ID | Tarefa | Responsável | Arquivos | Estado |
|---|---|---|---|---|
| T1 | Escopo de nomes, inventário e telemetria PG | collector_review | collector/, migração 003, SQL telemetria | CONCLUÍDA |
| T2 | Identidades, ECS, normalização e métricas ES | root | logstash/pipeline/, mappings/templates, validação | CONCLUÍDA |
| T3 | Dashboards e regras de detecção | data_pipeline_review | kibana/build.mjs, rules/, dist/, testes e guia | CONCLUÍDA |
| T4 | Acessos, certificados e deploy | ops_review | docker/, setups ES/Kibana, script TLS PG e guia | CONCLUÍDA |
| T5 | Integração e validação técnica local | root | testes existentes e verificações integradas | CONCLUÍDA |

## Decisões

- A exclusão por `note`/`micro` prevalece sobre a inclusão por `srv`/`fisico`.
- Inventário esperado vazio significa cobertura total desconhecida.
- Eventos recebidos não provam autorização de acesso nem sessão ainda conectada.
- Identidade principal pode usar SID; correlação também precisa funcionar quando
  somente domínio/nome estiverem presentes. Contextos sem domínio não são unidos
  arbitrariamente entre servidores.
- Índices mensais e IDs de eventos existentes serão preservados.
- Sem alterações destrutivas em dados existentes, commits ou deploy remoto.

## Validação

| Critério | Resultado | Evidência |
|---|---|---|
| Tipos e testes do coletor | APROVADO | 55 testes (8 integração) |
| Migrações e integração PostgreSQL 18 | APROVADO | bootstrap + 001/002/003 em containers próprios |
| Sintaxe e comportamento Logstash | APROVADO | 9 testes Ruby e ingestão real PG/ES TLS |
| Compose e scripts shell | APROVADO | validate.ps1 e testes TLS isolados |
| Pacote Kibana, referências e regras | APROVADO | 10 testes, 65 objetos, 8 regras importadas |
| Importação Kibana 9.5.5 | APROVADO | espaço soc, perfis e APIs reais |
| Renderização visual Kibana | NÃO EXECUTADO | navegador recusou CA privada local |

Evidências, limites e procedimentos em `VALIDACAO-EVOLUCAO.md`.

## Reversão

Repor os arquivos da versão anterior, preservando bancos, volumes e CA. Migração
aditiva não exige excluir os novos dados para executar a versão anterior.
Procedimentos concretos e ordem do deploy em `DEPLOY-EVOLUCAO.md`.
