# Dashboards SOC

O pacote `kibana/dist/objects.ndjson` é gerado por `node kibana/build.mjs` e importado no espaço **SOC**, id `soc`, pelo setup. Os links usam `/s/soc/`; não apontam para o espaço padrão. A importação atualiza os objetos com os mesmos IDs. Personalizações locais devem usar **Salvar como** com outro ID.

## Os cinco painéis

| Dashboard | Uso |
|---|---|
| SOC - Visão operacional | Incidentes/alertas Defender no estado conhecido, com alertas de detecção Elastic apresentados separadamente |
| SOC - Identidades e acessos | Logons, classificação de contas, escopo local/domínio, confiança da correlação e privilégio administrativo observado |
| SOC - Investigação por servidor | Seguir host.id e identidade entre logons, origens RDP, falhas e eventos detalhados |
| SOC - ASR | Auditoria e bloqueio ASR, processo, arquivo, hash e identidade observados |
| SOC - Cobertura e capacidade | Cadastro esperado versus Defender conhecido; sensores; execuções do coletor; tamanho do PostgreSQL e capacidade do processo/nó ES |

Eventos e inventário usam o escopo de nomes: contém **srv OU fisico**, exclui **note OU micro**. Eventos antigos fora desse escopo continuam armazenados e podem ser consultados diretamente no Discover. Incidentes e alertas Defender são dados do tenant e não recebem uma restrição artificial por nome de servidor.

## Tempo e significado dos totais

As views `soc-incidents`, `soc-alerts` e `soc-devices` **não possuem campo de tempo**. Seus cartões e tabelas mostram o estado conhecido inteiro, inclusive um incidente ainda ativo cuja última atualização é antiga. Isso não comprova coleta recente. A view adicional `soc-alerts-timeline` usa `@timestamp` para a distribuição por última atualização conhecida, respeitando o seletor temporal. Histórico de versões continua na view `soc-history`.

Alertas Defender (`soc-alerts`) vêm da Microsoft. Alertas Elastic (`.alerts-security.alerts-soc`) são resultados das regras executadas no espaço SOC; seus cartões respeitam o período selecionado. Não somar essas duas fontes como incidentes únicos.

## Identidades e investigação

Use **soc.identity.correlation_key** para filtros, cardinalidade e correlação entre falha e sucesso. A chave combina domínio/nome normalizados; contas locais são qualificadas pelo host. Isso evita juntar contas locais ou domínios diferentes só porque ambos usam `administrador`, sem separar uma falha sem SID de um sucesso com SID da mesma conta. `soc.identity.key` e `user.id` conservam a identidade preferencial por SID como detalhe. `soc.identity.display` é apenas apresentação.

`soc.identity.type` pode ser person, service, machine, system ou unknown. Uma conta que não termina em `$` não é automaticamente uma pessoa. `scope` e `confidence` tornam explícita a qualidade da classificação. `is_local_admin` representa informação observada no evento; não equivale a um levantamento completo dos membros do grupo Administradores.

No painel de investigação, adicione um filtro **host.id**. Clique nos valores das tabelas para incluir/excluir filtros e adicione **soc.identity.correlation_key** quando quiser seguir uma conta. Fixe os filtros que deseja manter ao navegar e confira o seletor de tempo no destino. O nome de apresentação não substitui o ID. Os links não transportam automaticamente filtros locais não fixados.

As tabelas Lens são **rankings limitados**, com limites declarados no título; não são uma exportação integral. Os painéis de documentos detalhados podem ser abertos no Discover, onde é possível ampliar colunas, inspecionar o payload e consultar sem o limite de top N das agregações. Não interpretar número de linhas exibidas como total do ambiente.

A matriz de acessos é uma tabela agrupada pelas 20 identidades com mais documentos e até 10 servidores por identidade, com contagens separadas de sucessos e falhas. Os dois eixos usam chaves canônicas; a tabela não cruza contas apenas pelo nome e não representa todas as combinações fora do top N.

## Cobertura e amostras de capacidade

O inventário esperado deve ser cadastrado explicitamente. **Zero esperados significa SEM CADASTRO**, não cobertura de 100%. Dispositivos conhecidos no Defender não comprovam que todos os servidores da empresa estão cobertos. Compare esperados e observados, onboarding, saúde do sensor, `last_seen` e `snapshot_at`; a tabela detalhada mostra os horários.

As métricas de coleta usam `event.dataset:soc.collector_status`, agrupadas por `soc.metrics.source`. Cada coluna numérica mostra a última amostra disponível para aquele campo no período. A tabela de execuções mostra status e horário reais; não inferir sucesso apenas porque houve eventos recebidos. Métricas de uma execução não são totais acumulados. A linha “Eventos” nessa tabela agregada conta amostras recebidas, não eventos Defender.

PostgreSQL usa `event.dataset:soc.database_capacity` e `soc.metrics.source:database.capacity`. Elasticsearch usa `event.dataset:soc.elasticsearch_capacity` e `soc.metrics.source:elasticsearch.capacity`. Os cartões usam **last_value ordenado por @timestamp**, nunca soma dos snapshots. Tamanhos são bytes; CPU é percentual do processo ES. Disco ES é o filesystem visto pelo nó. Esses indicadores não representam CPU/RAM das VMs ou dos servidores monitorados. Não há coleta automática de CPU/RAM dos hosts nesta rodada.

Escolher um período histórico mostra a última amostra daquele período, não o estado de agora. Campo vazio significa ausência de amostra nesse intervalo. Confira o timestamp no Discover antes de tomar decisões de capacidade.

Os gráficos de evolução PostgreSQL e Elasticsearch usam um histograma temporal e **last_value em cada intervalo**. Assim, aumentar a frequência de coleta não aumenta artificialmente o tamanho do banco ou o uso de heap. Intervalos sem amostra não são preenchidos como capacidade zero. A série “Banco total” contém as tabelas exibidas e outros objetos; não deve ser somada às séries por tabela.

## Regras v2 e implantação

As oito regras continuam em observação (`actions: []`), preservando intervalos e janelas de tempo. A versão 2 usa `soc.identity.correlation_key` e `host.id` nos agrupamentos, exige campos canônicos nos logons e aplica o escopo de nomes também às queries. ASR exige host.id, sem exigir identidade quando o evento não a fornece. A regra EQL mantém 5 falhas, sucesso e `maxspan=30m`; a troca é de chave de correlação.

Dados legados sem a nova normalização ficam disponíveis para consulta, mas não alimentam os novos agrupamentos/regras que exigem esses campos. A linha de base das regras new_terms precisa ser formada com os campos novos; haverá uma fase inicial com mais alertas. Não foi acrescentada supressão silenciosa para mascarar essa fase.

Validação local do pacote: `node kibana/build.mjs --check` e `node --test kibana/test/*.test.mjs`. Esses testes verificam estrutura, referências, layouts e contratos. Importação, migração dos objetos Lens/Discover, renderização e execução real das regras precisam ser verificadas no Kibana 9.5.5 implantado; os testes estáticos não substituem essa verificação.
