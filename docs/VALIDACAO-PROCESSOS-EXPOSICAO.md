# Validação — processos, rede e postura

Data: 21/10/2026 (America/Sao_Paulo). Coletor 0.3.0, Node 24, PostgreSQL 18 e
Elasticsearch/Kibana/Logstash 9.5.5. Verificações locais com dados sintéticos;
sem autenticação no Graph, acesso às VMs ou leitura do `.env` de implantação.

| Verificação | Resultado | Evidência |
|---|---|---|
| Migrações 001–004 / bootstrap idempotente | APROVADO | PostgreSQL 18 temporário em validate.ps1 |
| Tipos, build e testes do coletor | APROVADO | 80 testes: 69 unitários e 11 de integração PG |
| Normalizador e pipeline Logstash | APROVADO | 21 testes Ruby; Configuration OK em 9.5.5 |
| Mappings explícitos / template de postura | APROVADO | 4 testes de contrato |
| Pacote Kibana | APROVADO | 14 testes; 101 objetos, sete dashboards, oito regras existentes |
| Compose / scripts shell | APROVADO | validate.ps1; shellcheck |
| Ingestão PG → Logstash → ES e APIs Kibana | APROVADO | smoke-evolution.mjs; PG TLS verify-full |
| Atualização aditiva de índice existente | APROVADO | campos anteriores preservados e novos campos adicionados pelo setup |
| Perfis observer/analyst/admin | APROVADO | sete dashboards, leitura de postura, sem write/delete_index ou manage_security |
| Renderização visual no navegador | NÃO EXECUTADO | conferência visual no ambiente implantado |
| API Microsoft / licença e dados reais | NÃO EXECUTADO | depende do tenant; conferir na implantação |

## Casos cobertos

- Inclusão srv/fisico e exclusões note/micro, com maiúsculas e servidores fora
  do catálogo esperado. Defesa local na coleta nova e na normalização.
- Processo criado separado do iniciador; contas corretas por fonte e
  identificadores de instância preservados quando presentes.
- Endpoints locais/remotos tipados; ausência de inferências de direção e bytes.
- Identidade estável de postura com Context JSON canônico e distinção por
  servidor/CVE/vendor/software/versão ou servidor/configuração/contexto.
- Observado → não mais reportado → observado; conservação da chave e da data
  original de retirada para tombstones que continuam ausentes.
- Rollback conserva estado/checkpoint/publicação; snapshots anteriores,
  incompletos, no limite ou com erros explícitos não retiram itens atuais.
- Datas distintas para avaliação, snapshot e coleta; booleanos e CVSS ausentes
  permanecem desconhecidos. CVSS inválido fica no bruto sem criar score falso.
- Postura atual sem corte temporal, sempre filtrada por active. CVEs distintos
  separados de instâncias por software. Dados de exploração disponível sem
  afirmar exploração observada.
- Navegação entre sete dashboards, links Discover por host.id e última execução
  por fonte independente do período global, inclusive quando há falha.

## Limites

O laboratório testa contratos e comportamento com dados controlados. Não comprova
licença, disponibilidade das tabelas, permissões Microsoft, completude dos dados
que o serviço não reportou, vazão real ou aparência final com os dados do ambiente.
Snapshots aceitam menos de 10.000 linhas por fonte; ao atingir o limite, mantêm
estado anterior e falham visivelmente. A expansão exige estratégia de consulta
completa, sem simplesmente aumentar o limite de configuração.

Saúde detalhada de assinatura/motor/modo AV não está incluída. O painel usa saúde
do sensor e avaliações TVM. Retirada de um item não comprova correção; uma coleta
bem-sucedida não comprova contato recente do sensor. A frente de postura não
substitui o inventário completo nem a validação de exposição de rede.

## Resultado da integração

Sessão descartável `soc-evolution-5800521d`, removida após a validação. A fixture
produziu dois processos e duas conexões dos nomes permitidos; nenhum documento
dos nomes excluídos chegou aos índices de eventos ou postura. Três registros de
postura permaneceram ativos e o registro retirado continuou inativo mesmo após
republicação antiga. As quatro identidades homônimas permaneceram separadas.

Os datasets de métricas `soc.collector_status`, `soc.database_capacity` e
`soc.elasticsearch_capacity` ficaram pesquisáveis. A falha recente da fonte TVM
foi preservada com checkpoint antigo; não foi substituída por um resultado
saudável. Não foram encontrados erros de indexação 400 ou erros de nível ERROR
nos logs Logstash da sessão.

Kibana importou 101 objetos e oito regras. Observer consultou dashboards e não
gerenciou detecções; analyst consultou regras e criou Case, sem alterar regra;
admin SOC editou regra e recebeu recusa na administração da segurança do cluster.
Os três perfis têm leitura de `soc-posture`, sem escrita ou exclusão do índice.

## Reproduzir

```powershell
powershell -ExecutionPolicy Bypass -File scripts\validate.ps1
node scripts/lab/smoke-evolution.mjs
```

O smoke usa projeto Docker exclusivo, portas de loopback 15601/19200,
credenciais/CA temporárias e PG TLS verify-full. Remove apenas os recursos
criados por ele; não executa o coletor contra Graph nem aponta para as VMs.
