# Validação local — evolução do piloto

Data: 21/10/2026 (America/Sao_Paulo). Sem acesso às VMs implantadas ou ao Graph.
Código do coletor: 0.2.0. Stack exercitada: Elasticsearch/Kibana/Logstash 9.5.5,
PostgreSQL 18, Node 24. O laboratório utilizou projeto Docker exclusivo, dados
sintéticos, credenciais temporárias e volumes próprios; não usou `.env` real.

| Critério | Resultado | Evidência |
|---|---|---|
| Bootstrap e três migrações PostgreSQL | APROVADO | scripts/validate.ps1 e smoke-evolution.mjs |
| Tipos e testes do coletor | APROVADO | 55 testes, incluindo 8 de integração PG |
| Escopo de nomes | APROVADO | inclusão srv/fisico, exclusões prevalecem; teste integrado sem documentos note/micro |
| Inventário esperado/observado | APROVADO | promoção sem duplicação, rename, silenciosos; documentos sintéticos no ES |
| Logstash configuração e normalizador | APROVADO | config.test_and_exit, 9 testes Ruby independentes do catálogo real |
| JSON/mappings, referências e tipos Lens | APROVADO | 10 testes Kibana; bool/IP e last_value conferidos |
| Compose e scripts shell | APROVADO | configuração sintética, shellcheck |
| Importação Kibana 9.5.5 | APROVADO | 65 objetos / 5 dashboards, 8 regras no espaço soc |
| PG → Logstash → ES com verify-full | APROVADO | certificado DNS postgres no laboratório, dados indexados sem erro TLS |
| Métricas de capacidade | APROVADO | datasets soc.database_capacity e soc.elasticsearch_capacity pesquisáveis |
| Separação de contas | APROVADO | 4 identidades distintas para contas homônimas de domínios/hosts diferentes |
| Perfis de acesso funcionais | APROVADO | contas temporárias, endpoints reais e verificação de privilégios |
| TLS PG e exportação Elastic | APROVADO | emissão/SAN/renovação/idempotência/recusas; CA e leafs preservados |
| Renderização visual no navegador | NÃO EXECUTADO | navegador recusou a CA privada local; não foi contornado o bloqueio |
| Graph real e operação nas VMs Ubuntu | NÃO EXECUTADO | deploy será feito pelo responsável |

## Acessos exercitados

Observer consultou os cinco dashboards e não pôde consultar/gerenciar regras.
Analyst consultou regras e criou um Case SOC, mas alteração de regra retornou 403.
Admin SOC editou regra sem superuser; administração de segurança retornou 403.
Os três perfis receberam leitura de eventos/alertas SOC, sem write/delete_index
nos índices históricos e sem manage_security.

## Limitações observadas

A importação dos objetos não comprova a aparência final das telas. Conferir
renderização e filtros com os dados reais após o deploy. O inventário não comprova
que todas as máquinas da empresa possuem Defender, nem que o sensor está online
agora. Os catálogos esperados/de classificação começam vazios intencionalmente.

As regras importadas executaram no laboratório e geraram alertas. Na carga inicial
sintética, algumas atingiram o limite já existente de 100 alertas por execução;
o Kibana reportou execução parcial por limite. Esse limite foi preservado e deve
ser avaliado na observação, em especial durante a formação da linha de base.
Não foi medida eficácia/falso positivo contra tráfego real.

Backup/restauração, quarentena e garantias de atraso/durabilidade não foram
alterados. Os procedimentos de TLS são preparados para Ubuntu 26.04/PostgreSQL18,
mas não foram aplicados às VMs reais. Não houve commits ou deploy remoto.

## Repetir

```powershell
powershell -ExecutionPolicy Bypass -File scripts\validate.ps1
node scripts/lab/smoke-evolution.mjs
```

O smoke não inicia o coletor e não chama o Graph. Precisa das portas locais
15601/19200 livres e de recursos para a stack temporária. Nunca aponte os scripts
de dados sintéticos para o PostgreSQL implantado.
