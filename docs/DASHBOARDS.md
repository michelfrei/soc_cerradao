# Dashboards SOC

O pacote `kibana/dist/objects.ndjson` é gerado por `node kibana/build.mjs` e importado no espaço **SOC**, id `soc`, pelo setup. Os links usam `/s/soc/`; não apontam para o espaço padrão. A importação atualiza os objetos com os mesmos IDs. Personalizações locais devem usar **Salvar como** com outro ID.

## Os oito painéis

| Dashboard | Uso |
|---|---|
| SOC - Visão operacional | Incidentes/alertas Defender no estado conhecido, com alertas de detecção Elastic apresentados separadamente |
| SOC - Identidades e acessos | Logons, classificação de contas, escopo local/domínio, confiança da correlação e privilégio administrativo observado |
| SOC - Investigação por servidor | Seguir host.id e identidade entre logons, origens RDP, falhas e eventos detalhados |
| SOC - ASR | Auditoria e bloqueio ASR, processo, arquivo, hash e identidade observados |
| SOC - Cobertura e capacidade | Cadastro esperado versus Defender conhecido; sensores; execuções do coletor; tamanho do PostgreSQL e capacidade do processo/nó ES |
| SOC - Processos e conexões | Processo criado/iniciador, comandos, conta e endpoints local/remoto; correlação por host.id e process.entity_id |
| SOC - Exposição e proteção | Exposição reportada pelo Defender, CVEs/software, avaliações de configuração, dados desconhecidos e datas das fontes |
| SOC - Acessos aos servidores | Visão consolidada (porte do painel Grafana): 9 indicadores, 10 pontos de atenção por severidade, tempo, mapa de calor servidor × hora, rankings, negados agrupados e admin em RDP/console, com controles de filtro |

## Acessos aos servidores

Período padrão: últimas 24 h. Os controles no topo (servidor, conta, tipo de acesso, resultado,
origem) e qualquer clique em valor de gráfico ou tabela filtram o painel inteiro; os filtros
podem ser fixados para seguir a outros painéis.

| Ponto de atenção | Critério (além do escopo de servidores) |
|---|---|
| 🔴 Acesso de IP público | `source.ip` fora de 10/8, 172.16/12, 192.168/16, 127/8, 169.254/16, ::1, fe80::/10, fc00::/7; tipos Network, RemoteInteractive, NetworkCleartext |
| 🔴 Possível password spraying | Falhas (exceto Service/Batch), por origem, ordenado por contas distintas |
| 🟠 Senha em texto claro | `NetworkCleartext`; crítico quando há sucesso |
| 🟠 Contas bloqueadas | `event.reason: AccountLocked`; coluna de privilégio vem do catálogo de identidades |
| 🟠 Contas genéricas em RDP/console | `soc.identity.generic` (nome sem domínio: administrator, admin, guest, convidado, suporte, backup, sa, ti… com sufixo numérico opcional) |
| 🟠 Fora do horário | `soc.time.off_hours`: 22h–6h ou sábado/domingo em Brasília (UTC-3); tipos humanos |
| 🟠 Rajadas de falha | Falhas por conta, servidor e motivo |
| 🔵 Contas em muitos servidores | Servidores distintos via rede/RDP (coluna separada só RDP) |
| 🔵 NewCredentials | `runas /netonly` |
| 🔵 Contas locais via rede/RDP | `soc.identity.scope: local` com sucesso remoto |

Os campos `soc.time.*` e `soc.identity.generic` são calculados no Logstash (`normalize.rb`).
Eventos indexados antes da sua introdução só os recebem após `CALL soc.republish_events(...)`.
Ajuste a lista de contas genéricas ou o horário comercial em `normalize.rb` (`GENERIC_ACCOUNT`,
`local_time`) conforme a operação — turnos e safra podem tornar o acesso noturno normal.

Eventos e inventário usam o escopo de nomes: contém **srv OU fisico**, exclui **note OU micro**. Eventos antigos fora desse escopo continuam armazenados e podem ser consultados diretamente no Discover. Incidentes e alertas Defender são dados do tenant e não recebem uma restrição artificial por nome de servidor.

## Tempo e significado dos totais

As views `soc-incidents`, `soc-alerts` e `soc-devices` **não possuem campo de tempo**. Seus cartões e tabelas mostram o estado conhecido inteiro, inclusive um incidente ainda ativo cuja última atualização é antiga. Isso não comprova coleta recente. A view adicional `soc-alerts-timeline` usa `@timestamp` para a distribuição por última atualização conhecida, respeitando o seletor temporal. Histórico de versões continua na view `soc-history`.

A view `soc-posture` também não possui campo de tempo e filtra
`soc.posture.active:true`. Snapshots completos retiram itens não mais reportados;
isso não comprova correção. A view `soc-metrics-current`, sem campo de tempo,
permite consultar a última execução conhecida por fonte mesmo fora do período
selecionado. Confira status, conclusão, snapshot, data de avaliação e último
contato do sensor antes de interpretar cartões vazios ou resultados anteriores.

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

## Processos, rede e postura

Em criação de processos, `process.*` representa o processo criado e
`process.parent.*` seu iniciador. Na rede, `process.*` representa o iniciador da
conexão. Use `host.id` junto de `process.entity_id` quando disponível; PID pode ser
reutilizado. Um link de `host.id` abre o Discover na fonte correspondente. Para
correlacionar outras fontes, aplique o mesmo filtro e confira o período.

IPs e portas de rede usam `soc.network.local_*` e `remote_*`. Essa perspectiva
não permite inferir direção, bytes, exfiltração ou malícia. Os rankings mostram
atividade observada; o Defender não fornece um inventário completo de conexões
ativas por essas tabelas.

Uma vulnerabilidade é armazenada por servidor/CVE/vendor/software/versão. O painel
separa instâncias de CVEs distintos e servidores distintos; cardinalidades são
aproximadas. A prioridade high/critical com exploit público disponível não é
evidência de exploração. Avaliação não aplicável não é falha; booleano ausente é
desconhecido. `IsInternetFacing` ausente também é desconhecido.

A proteção mostrada inclui saúde do sensor e avaliações TVM, sem exportação
detalhada das versões de assinatura/motor ou modo AV. Os sinais operacionais de
contato antigo (24 h) e snapshot antigo (36 h) indicam necessidade de conferir a
coleta, sem concluir comprometimento. Campos originais permanecem em `defender`.

Ativação e limites das fontes: [DEPLOY-PROCESSOS-EXPOSICAO.md](DEPLOY-PROCESSOS-EXPOSICAO.md).

## Regras v2 e implantação

As oito regras continuam em observação (`actions: []`), preservando intervalos e janelas de tempo. A versão 2 usa `soc.identity.correlation_key` e `host.id` nos agrupamentos, exige campos canônicos nos logons e aplica o escopo de nomes também às queries. ASR exige host.id, sem exigir identidade quando o evento não a fornece. A regra EQL mantém 5 falhas, sucesso e `maxspan=30m`; a troca é de chave de correlação.

Dados legados sem a nova normalização ficam disponíveis para consulta, mas não alimentam os novos agrupamentos/regras que exigem esses campos. A linha de base das regras new_terms precisa ser formada com os campos novos; haverá uma fase inicial com mais alertas. Não foi acrescentada supressão silenciosa para mascarar essa fase.

Validação local do pacote: `node kibana/build.mjs --check` e `node --test kibana/test/*.test.mjs`. Esses testes verificam estrutura, referências, layouts e contratos. Importação, migração dos objetos Lens/Discover, renderização e execução real das regras precisam ser verificadas no Kibana 9.5.5 implantado; os testes estáticos não substituem essa verificação.
