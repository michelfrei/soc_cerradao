# Detecções — piloto SOC (modo observação)

Regras do Elastic Security (Kibana 9.5.5, licença basic) em `kibana/rules/<rule_id>.json`, no formato do corpo de `POST /api/detection_engine/rules` (importação via `_import` após conversão para NDJSON).
Todas: `enabled: true`, `actions: []` (sem notificação), tags `SOC`, `SOC-observacao`, `Frente N`; índice `soc-events-*`; `max_signals` 100; `version` 1.
Estado: **validadas em laboratório** (21/10/2026) — as 8 regras foram importadas pelo `kibana-setup`, executaram sem erro e geraram alertas com os dados de `scripts/lab/dados-sinteticos.sql` e `scripts/lab/cenarios-deteccao.sql`. Ainda não avaliadas com dados reais (taxa de falso positivo desconhecida).

## Regras

| rule_id | Frente | Tipo | Lógica resumida | Sev. (risk) | MITRE |
|---|---|---|---|---|---|
| soc-rdp-origem-nova-servidor | 1, 4 | new_terms | Logon `RemoteInteractive` com sucesso; par novo `host.name`+`source.ip` vs. 14 d | medium (47) | T1021.001; T1078 |
| soc-par-usuario-servidor-novo | 1 | new_terms | Logon `Interactive`/`RemoteInteractive`/`CachedInteractive` com sucesso; par novo `user.name`+`host.name` vs. 14 d | low (21) | T1078 |
| soc-conta-muitos-servidores | 4 | threshold | Sucesso `Network`/`RemoteInteractive`; por `user.name`, ≥5 `host.name` distintos em ~70 min | high (73) | T1021.001/.002; T1078 |
| soc-rajada-falhas-logon | 1 | threshold | Falhas (inclui agregadas) por `host.name`+`user.name` ≥10 em ~70 min; sem Service/Batch | medium (47) | T1110.001 |
| soc-forca-bruta-sucesso | 1 | eql | `sequence by user.name maxspan=30m`: 5 falhas (`runs=5`) → 1 sucesso | high (73) | T1110.001/.003; T1078 |
| soc-asr-bloqueio | 3 | query | `soc.asr.mode:"block"`, exceto LsassCredentialTheft e PsexecWmiChildProcess | medium (47) | TA0002 (sem técnica: depende da regra ASR) |
| soc-asr-lsass-roubo-credencial | 3, 1 | query | `soc.asr.rule:"LsassCredentialTheft"` (audit ou block) | high (73) | T1003.001 |
| soc-asr-psexec-wmi | 3, 4 | query | `soc.asr.rule:"PsexecWmiChildProcess"` (audit ou block) | medium (47) | T1047; T1569.002; T1021.002 |

Exclusões comuns às regras de logon: contas de máquina (`user.name` terminando em `$`). Específicas: `Window Manager`/`Font Driver Host` (DWM-/UMFD-) na regra de par novo; `NT AUTHORITY` e `ANONYMOUS LOGON` na de muitos servidores; tipos `Service`/`Batch` nas de falha.

## Agendamento e atraso

| Regras | interval | from | Motivo |
|---|---|---|---|
| new_terms e ASR (query) | 10m | now-30m | `timestamp_override: "event.ingested"`: a janela olha a hora em que o evento chegou ao ES, então eventos atrasados (inclusive os da reconciliação de 24 h) são avaliados quando chegam |
| eql de logon | 10m | now-2h | Usa `@timestamp`: a ordem real dos eventos importa na sequência |
| threshold | 10m | now-70m | Usa `@timestamp`: a janela do threshold é o próprio `from`; ~70 min tolera ~40 min de atraso para rajadas curtas |

**Lacuna conhecida:** eventos de logon com mais de ~1 h de atraso não entram nas regras de threshold e EQL (a sequência/contagem é por horário do evento).
**Efeito colateral:** republicar eventos (`CALL soc.republish_events`) atualiza `event.ingested` e pode gerar novamente alertas nas regras `query` (ASR).

## Premissas

- `user.name`, `host.name`, `user.domain`, `winlog.logon.type`, `soc.asr.*`, `event.*` são `keyword` (KQL/EQL exatos, sensíveis a maiúsculas). `user.name` do Defender costuma vir em minúsculas; as exclusões de `NT AUTHORITY`/`ANONYMOUS LOGON` cobrem as duas grafias.
- `event.outcome` vale `success`/`failure` também para `*AggregatedReport`. Um evento agregado conta como **1** documento: thresholds e `runs=5` subestimam a repetição real. Recomendação: extrair a contagem de `AdditionalFields` para campo numérico e migrar a rajada para ES|QL com `SUM`.
- new_terms: o histórico de 14 d precisa existir no índice. Nos primeiros 14 dias de dados (ou após incluir um servidor novo na coleta) haverá excesso de alertas — esperado em observação.
- Somente servidores com "srv"/"fisico" no nome têm DeviceLogonEvents; logons em estações não são vistos.
- `source.ip` pode vir vazio em logons RDP via gateway; a regra de RDP exige `source.ip` presente.

## Falsos positivos e exceções

| Regra | Principais FPs | Exceção sugerida |
|---|---|---|
| RDP origem nova | Estação nova de admin, pool VPN novo, jump server | `source.ip` (rede de admin/jump server) |
| Par usuário→servidor | Novo colaborador, fornecedor pontual | `user.name` + `host.name` |
| Muitos servidores | Contas de backup, AV, inventário, scanner, SCCM; patch em lote | `user.name` da conta de serviço |
| Rajada de falhas | Senha antiga em app/unidade mapeada/celular | `user.name` + `host.name`, revisando `event.reason` antes |
| Força bruta → sucesso | Usuário errou e acertou | Somente após revisão; preferir ajustar `runs` |
| ASR bloqueio | Aplicação de negócio/instalador legítimo | `soc.asr.rule` + `file.path` ou `file.hash.sha256` |
| ASR LSASS | AV/EDR de terceiros, backup, monitoramento | `process.name` + `file.hash.sha256` (nunca só o nome) |
| ASR PsExec/WMI | SCCM, monitoramento via WMI | `process.parent.name` + `process.command_line` |

Como criar: Security → Rules → regra → **Rule exceptions** → *Add rule exception* (condições AND sobre os campos acima; marque "fechar alertas existentes que correspondam" se desejar). Para exceção reutilizável entre regras, use **Shared exception lists**. Prefira condições combinadas (conta + host/hash) a exclusões amplas. Registre o motivo no comentário da exceção. Alterar a query exige incrementar `version`.

## Testes (eventos sintéticos)

Convenções: `T` = instante da execução da regra; horários são `@timestamp` do evento (UTC). Todo documento de logon leva `event.kind:"event"`, `event.module:"defender"`, `event.dataset:"defender.devicelogonevents"`; ASR leva `event.dataset:"defender.deviceevents"`. Indexe em `soc-events-devicelogonevents-AAAA.MM` / `soc-events-deviceevents-AAAA.MM` do mês do evento **antes** da execução. Campos omitidos podem ficar ausentes.

### soc-rdp-origem-nova-servidor
- Histórico: `T-5d` LogonSuccess, `outcome:success`, `winlog.logon.type:RemoteInteractive`, `host.name:srvapp01`, `source.ip:10.0.0.10`, `user.name:joao`.
- **Dispara:** `T-30m` mesmo tipo/host, `source.ip:10.0.5.99`, `user.name:joao`.
- **Não dispara:** `T-30m` `source.ip:10.0.0.10` (já visto); `T-30m` `source.ip:10.0.5.99` com `user.name:srvapp01$`; `T-30m` `type:Network`; `T-30m` `outcome:failure`; `T-3h` origem nova (fora do `from`).

### soc-par-usuario-servidor-novo
- Histórico: `T-3d` sucesso `Interactive`, `user.name:maria`, `host.name:srvarq01`.
- **Dispara:** `T-20m` sucesso `RemoteInteractive`, `user.name:maria`, `host.name:srvsql01`.
- **Não dispara:** `T-20m` `maria`@`srvarq01` (já visto); `T-20m` `maria`@`srvsql01` com `type:Network`; `T-20m` `user.name:dwm-1`, `user.domain:Window Manager`; `user.name:srvsql01$`.

### soc-conta-muitos-servidores
- **Dispara:** `user.name:svc_teste`, sucesso, `type:Network`, `host.name` = srv01..srv05 (5 eventos) entre `T-40m` e `T-30m`.
- **Não dispara:** mesmos 5 eventos com 4 hosts distintos (um repetido); 5 hosts com `user.name:pc01$`; 5 hosts com `outcome:failure`; 5 hosts com `type:Batch`; 5 hosts espalhados entre `T-3h` e `T-10m` (só 3 dentro de 70 min).

### soc-rajada-falhas-logon
- **Dispara:** 10 eventos LogonFailed, `outcome:failure`, `type:Network`, `user.name:admin.teste`, `host.name:srvapp01`, `event.reason:InvalidUserNameOrPassword`, a cada 1 min de `T-30m` a `T-21m` (pode misturar LogonFailedAggregatedReport).
- **Não dispara:** 9 eventos; 10 eventos divididos em 2 hosts (5+5); 10 eventos com `type:Service`; 10 eventos com `user.name:srvapp01$`; 10 eventos em `T-3h`.

### soc-forca-bruta-sucesso
- **Dispara:** `user.name:carlos`, 5 falhas (`outcome:failure`, `type:Network`, `host.name:srvapp01`) em `T-40m`, `-39m`, `-38m`, `-37m`, `-36m`; sucesso `type:RemoteInteractive`, `host.name:srvapp02` em `T-35m`.
- **Não dispara:** 4 falhas + sucesso; 5 falhas a partir de `T-40m` e sucesso em `T-9m` (31 min após a primeira falha, fora de `maxspan=30m`); sucesso **antes** das falhas; falhas de `carlos` e sucesso de `ana`; mesma sequência com `type:Service`; mesma sequência com `user.name:pc01$`.

### soc-asr-bloqueio
- **Dispara:** `T-1h` `event.action:AsrOfficeChildProcessBlocked`, `soc.asr.rule:OfficeChildProcess`, `soc.asr.mode:block`, `host.name:srvapp01`, `process.name:winword.exe`, `file.name:cmd.exe`. Também em `T-20h` (cobertura 26 h).
- **Não dispara:** `AsrAbusedSystemToolAudited` (`mode:audit`); `AsrLsassCredentialTheftBlocked` (`rule:LsassCredentialTheft`, `mode:block`) — vai para a regra LSASS; `mode:block` em `T-27h`.

### soc-asr-lsass-roubo-credencial
- **Dispara:** `T-30m` `event.action:AsrLsassCredentialTheftAudited`, `soc.asr.rule:LsassCredentialTheft`, `soc.asr.mode:audit`, `process.name:procdump64.exe`, `file.name:lsass.exe`. Também com `mode:block`.
- **Não dispara:** `soc.asr.rule:AbusedSystemTool`; evento LSASS em `T-27h`; evento de logon com `soc.asr.rule` ausente.

### soc-asr-psexec-wmi
- **Dispara:** `T-30m` `event.action:AsrPsexecWmiChildProcessAudited`, `soc.asr.rule:PsexecWmiChildProcess`, `soc.asr.mode:audit`, `process.name:wmiprvse.exe`, `process.command_line:"cmd.exe /c whoami"`. Também `mode:block` (não duplica em soc-asr-bloqueio).
- **Não dispara:** `soc.asr.rule:LsassCredentialTheft`; `PsexecWmiChildProcess` em `T-27h`.

Observação de teste: alertas são deduplicados por documento (query/new_terms/eql) e por histórico de bucket (threshold); reexecutar a regra sobre os mesmos dados não gera novo alerta.
