# Processos, conexões e exposição — plano da entrega

- Projeto: `C:\dev\soc`; PostgreSQL 18 e Elastic 9.5.5 em duas VMs Ubuntu 26.04.
- Autorização: implementação local solicitada pelo responsável em 2026-10-21.
- Estado: CONCLUÍDA a implementação e a validação local; implantação e conferência
  dos dados reais nas VMs serão feitas pelo responsável.

## Objetivo

Acrescentar processos executados, conexões associadas aos processos, exposição
dos servidores, vulnerabilidades e avaliações de configuração. Manter logs de
todos os nomes contendo `srv` ou `fisico`, sempre excluindo `note` ou `micro`, sem
diferenciar maiúsculas. O catálogo de ativos não limita a coleta.

## Responsabilidades

| Frente | Agente / papéis da biblioteca | Arquivos | Estado |
|---|---|---|---|
| Coleta e estado atual | collector_review / backend, DBA, segurança | collector/, migração 004 | Concluída |
| Normalização e índices | data_pipeline_review / segurança, Elasticsearch | logstash/, elasticsearch/ | Concluída |
| Visualizações e acessos | ops_review / segurança, Kibana | kibana/ | Concluída |
| Integração, laboratório e guia de implantação | root / coordenação, DevOps, revisão | docker/, scripts/, docs/ | Concluída |

Biblioteca de referência: `C:\Users\mcouto\OneDrive - Usina Cerradao\Documentos\projetos\AGENTES-MULTI-IA`.

## Decisões e critérios de aceite

- Processos: distinguir o processo criado do iniciador/pai, preservar argumentos,
  conta, hashes e identificadores sem criar vínculos quando o dado não existir.
- Rede: explicitar as perspectivas local/remota; não inferir direção de tráfego,
  volume transferido ou exfiltração a partir de eventos de conexão.
- Fontes novas de eventos começam com uma hora de histórico e janelas de quinze
  minutos, com divisão de janelas quando a API atingir o limite de resultados.
- Postura: estado atual separado dos eventos. Somente um snapshot completo e
  validado pode retirar itens da lista atual. Ausência posterior significa
  "não mais reportado", sem comprovar correção. Falha não zera resultados.
- Proteção nesta etapa usa saúde do sensor e avaliações de configuração TVM.
  Exportação detalhada de saúde do antivírus (`deviceavinfo`) fica para uma
  integração posterior com autorização própria da API Defender for Endpoint.
- Dados ausentes/desatualizados devem ser visíveis. Zero resultados não prova
  ausência de risco. Exploit público disponível não prova exploração observada.
- Migração aditiva; preservar dados, checkpoints, identidades e regras existentes.
- Verificar tipos, testes do coletor, PG18, normalizador, mappings, pacote Kibana,
  importação real e permissões em laboratório isolado, sem Graph real.

## Limites

Não há implantação remota, alteração no tenant Microsoft, leitura de segredos,
commit/push ou mudança de backup, quarentena e garantias de atraso nesta etapa.
Disponibilidade/licença das tabelas Microsoft depende do tenant e deve ser
conferida na implantação. Testes sintéticos não confirmam permissões reais.

## Evidência final

119 testes aprovados: 80 do coletor (11 com PG real), 21 do normalizador,
14 do pacote Kibana e quatro de mappings. Integração PostgreSQL 18 → Logstash →
Elasticsearch 9.5.5 com TLS verify-full aprovada; 101 objetos e oito regras
importados no Kibana, sete dashboards acessíveis pelos perfis previstos, sem
permissão de escrita nos eventos ou postura. Atualização aditiva de índice
existente e recusa de versão antiga de postura verificadas.

Procedimentos e limites em [VALIDACAO-PROCESSOS-EXPOSICAO.md](VALIDACAO-PROCESSOS-EXPOSICAO.md)
e [DEPLOY-PROCESSOS-EXPOSICAO.md](DEPLOY-PROCESSOS-EXPOSICAO.md).
