# Insights de remediação (Defender → Elastic)

Transforma a postura TVM coletada pelo coletor em **ações**: "atualizar este
aplicativo resolve estas CVEs", "esta GPO trata estas configurações", "este
software precisa ser substituído". O Defender é a fonte dos achados; o índice
`soc-insights` guarda as ações, prioridades, evidências e o acompanhamento.

## Fluxo

```
snapshot.devicetvmsoftwarevulnerabilities ─┐
snapshot.devicetvmsecureconfigurationassessment ─┼─> soc.posture_state ─┐
snapshot.devicetvmsoftwareinventory (fim de suporte) ┘                  ├─> insights.remediation ─> soc.remediation_insight
inventory.deviceinfo (exposição, valor, criticidade) ─> soc.device_inventory ┘        └─> soc.publication ─> Logstash ─> soc-insights
```

A fonte `insights.remediation` (a cada 6 h) não chama o Graph: lê o estado atual
do PostgreSQL numa transação `REPEATABLE READ` e grava estado e publicação na
mesma transação. Sem snapshot concluído de vulnerabilidades **e** configurações,
a execução falha visivelmente e não altera nada; nunca encerra ações por falta
de dados. Escopo de servidores igual ao resto do projeto (srv/fisico, exclui
note/micro).

## Blocos de remediação

Cada achado ativo entra em **um único** bloco:

| `category` | Regra de agrupamento | Chave |
|---|---|---|
| `windows_update` | CVE do sistema operacional (`microsoft/windows_server_*`, `windows_10/11`…) | SO: a LCU mais recente é cumulativa e trata as CVEs dos KBs anteriores, que ficam em `recommendation_ids` como evidência. Server 2016 registra a dependência da SSU |
| `application_update` | Demais softwares | fornecedor + produto (todas as versões juntas) |
| `driver_firmware` | Nome contém firmware/bios/driver (heurística, registrada em `data_gaps`) ou regra do catálogo | fornecedor + produto |
| `software_replacement` | `EndOfSupportStatus` de software (EOS/Upcoming EOS Software) | fornecedor + produto, inclusive sem CVE ativo |
| `gpo_configuration` / `script_manual` | `scid` vinculado em `configuration_ids` de uma entrada do catálogo | chave da entrada (vários scid podem compartilhar uma GPO) |
| `investigation` | Configuração aplicável não conforme sem vínculo no catálogo | scid |

Versão sem suporte (EOS Version) entra no bloco de atualização do próprio
software. Avaliações não aplicáveis, conformes ou com conformidade desconhecida
não geram ação (o painel Exposição e proteção já mostra as desconhecidas).

`remediation_type`: `definitive` quando a ação elimina o achado reportado;
`mitigation` quando apenas reduz o risco (entradas do catálogo podem declarar);
`undetermined` em investigação. Configurações por GPO tornam a avaliação
conforme e por isso são `definitive` para aquele achado.

## Prioridade

Não usa só CVSS. Pontuação (`priority_score`) e justificativa (`risk_rationale`):

| Fator | Pontos |
|---|---|
| Exploit público disponível em alguma CVE | +40 |
| Severidade máxima crítica / alta / média | +25 / +15 / +5 |
| CVSS ≥ 9 | +5 |
| Impacto da configuração ≥ 7 / ≥ 4 | +20 / +10 |
| Servidor exposto à Internet | +20 |
| Servidor de alto valor, exposição alta ou criticidade alta (`assets.json`) | +15 |
| Abrangência ≥ 10 / ≥ 3 servidores | +10 / +5 |
| Software sem suporte do fabricante | +15 |

P1 ≥ 70 (crítica), P2 ≥ 45 (alta), P3 ≥ 25 (média), P4 abaixo. Exploit
disponível não comprova exploração observada.

## Contrato do documento (`schema_version` 1.0)

Campos na raiz do índice `soc-insights` (mapeamento próprio, `dynamic: false`):

| Campo | Tipo | Observação |
|---|---|---|
| `@timestamp` | date | Horário do cálculo |
| `schema_version`, `analysis_id`, `insight_id`, `grouping_key` | keyword | `analysis_id` = `soc-insights-AAAAMMDDTHHMMSSZ` da execução |
| `source.name`, `source.tables`, `source.finding_ids`, `source.finding_count`, `source.snapshot_at` | keyword/integer/flattened | `finding_ids` = `_id` dos documentos em `soc-posture` (auditoria) |
| `title`, `description`, `risk_rationale` | text | |
| `category`, `remediation_type`, `priority`, `priority_label`, `effort`, `owner`, `status` | keyword | |
| `priority_score` | integer | |
| `cve_ids`, `cve_count`, `recommendation_ids` | keyword/integer | `recommendation_ids` = scid e KB |
| `affected_products[].vendor/name/versions` | keyword | |
| `affected_device_count`, `affected_device_ids`, `affected_devices` | integer/keyword | servidores únicos **desta** ação |
| `internet_facing_device_count`, `high_value_device_count` | integer | **ausente = desconhecido**, nunca zero |
| `exploit_available` | boolean | ausente = desconhecido |
| `max_severity`, `max_cvss`, `end_of_support` | keyword/double/keyword | |
| `remediation_steps`, `validation_steps`, `rollback_steps`, `dependencies` | text | |
| `gpo_name`, `gpo_settings[].scope/path/policy/value/registry/os_requirements/admx` | keyword | só para entradas validadas do catálogo |
| `scope_guidance`, `server_notes`, `dc_notes`, `compatibility_risks`, `operational_impact` | text | |
| `expected_outcome.summary/finding_reduction/cve_reduction/device_reduction/basis` | text/integer | redução só quando sustentada (ver abaixo) |
| `references` | keyword | URLs oficiais (Learn, MSRC, support.microsoft.com, NVD) |
| `data_gaps` | text | lacunas explícitas da evidência |
| `suggested_catalog_key` | keyword | sugestão **não decisória** para investigação |
| `first_seen`, `last_seen`, `resolved_at` | date | |

**`insight_id`** = `ins-` + 32 primeiros hex de `sha256(JSON canônico [category, chave de agrupamento])`.
A chave é a da tabela de blocos (ex.: `["windows_update","windows_server_2019"]`,
`["application_update","google|chrome"]`, `["gpo_configuration","smb-signing"]`).
Não depende de dispositivos, CVEs, datas nem do texto: reprocessar atualiza o mesmo
documento. Muda somente se a ação mudar — por exemplo, um scid em investigação que
passa a ser catalogado gera novo ID de GPO e a investigação fica `no_longer_reported`.

**Redução esperada:** em ações definitivas, `finding_reduction` = achados do bloco
(cada achado pertence a um único bloco e a ação é a que o Defender indica para
ele). `device_reduction` fica nulo: o servidor pode ter achados em outros blocos.
Mitigação e investigação não estimam redução.

**Status:** `open` enquanto houver achado ativo; `no_longer_reported` quando o
Defender deixa de reportar todos (com `resolved_at`, mantendo a última evidência).
Isso **não comprova correção**: pode ser remoção, perda de cobertura ou mudança
de escopo. Reaparecimento volta a `open` com o `first_seen` original.

## Catálogo de GPOs e ações

`collector/config/remediation-catalog.json` (montado no container; editar e
reiniciar o coletor). Validado na inicialização: arquivo inválido impede a subida.

- 16 entradas verificadas em documentação oficial Microsoft em 22/10/2026 (SMBv1,
  assinatura SMB, NTLMv2, hash LM, LLMNR, WDigest, LSA protection, RDP NLA,
  AutoPlay/AutoRun, Defender AV PUA/nuvem/tempo real, firewall, acesso anônimo,
  Print Spooler, PowerShell 2.0). Onde a fonte oficial não informa o valor do
  registro, o campo diz isso em vez de presumir.
- **Vínculo scid → entrada:** só `scid-91` (monitoramento de comportamento) tem
  fonte oficial e já vem vinculado. A Microsoft não publica lista de scid; os
  demais ficam em `investigation` até a equipe confirmar o scid do ambiente e
  incluí-lo em `configuration_ids`. `name_hints` apenas sugere a entrada.
- Para descobrir os scid do tenant (Advanced Hunting, somente leitura):

```kusto
DeviceTvmSecureConfigurationAssessmentKB
| where ConfigurationName has_any ("SMB", "LAN Manager", "multicast", "WDigest", "LSA", "Network Level",
    "Autoplay", "AutoRun", "potentially unwanted", "MAPS", "real-time", "Firewall", "Spooler", "PowerShell", "anonymous")
| project ConfigurationId, ConfigurationName, ConfigurationCategory, RemediationOptions
```

  Confira que o nome/remediação do scid corresponde exatamente à política da
  entrada antes de vincular. Um scid só pode pertencer a uma entrada.
- `software_rules` força a categoria de um software (ex.: firmware atualizado pela
  console do fabricante) com nota e responsável.
- Itens não confirmados e fora do catálogo: "Windows Defender Firewall: Protect
  all network connections" (substituído pelo estado do firewall por perfil), caminho
  GPO do serviço Spooler e nome oficial do recurso PowerShell 2.0 para cmdlets.

## Limites

- IDs de recomendação do portal (`va-_-…`, `sca-_-…`) não saem pelo Advanced
  Hunting; exigem a API do Defender for Endpoint com outra autorização.
- O Defender documenta fim de suporte apenas para produtos Windows; para os demais
  a lacuna aparece em `data_gaps`. Os valores exatos de `EndOfSupportStatus` não são
  documentados: o coletor reconhece "software"/"version"/"upcoming" no texto.
- Snapshots TVM são consultados em partes por `hash(DeviceId)` (`partitions` em
  `sources.json`: 8 para vulnerabilidades e configurações, 2 para fim de suporte).
  Cada parte aceita até 10.000 linhas; se qualquer parte atingir o limite, o
  snapshot inteiro é recusado e o erro pede para aumentar `partitions` (até 64).
  O Advanced Hunting limita cada consulta a 100.000 linhas e 64 MB.
- O acompanhamento operacional (quem executa, prazo) não é escrito neste índice:
  cada recálculo regrava o documento. Use Cases do Kibana referenciando o
  `insight_id`.
- Classificação driver/firmware por nome é heurística e marcada como tal.
