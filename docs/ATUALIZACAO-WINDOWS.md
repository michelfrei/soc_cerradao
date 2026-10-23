# Atualização do Windows nos servidores SRV*

Dashboard **SOC - Atualização do Windows** (espaço `soc`). Mostra, por servidor
cujo nome começa com `SRV` (sem diferenciar caixa) e roda Windows Server, se a
atualização de segurança do sistema operacional está em dia. Não instala nada e
não reinicia servidores.

## Fontes (decisão: somente Defender + catálogo Microsoft)

| Dado | Fonte | Observação |
|---|---|---|
| Servidores, versão do Windows, último contato | Defender `DeviceInfo` (fonte `inventory.deviceinfo`) | `OSPlatform` = WindowsServer2016/2019/2022 |
| Build completa (ex.: 10.0.20348.4405) | Defender `DeviceTvmSoftwareInventory`, linha do próprio SO (fonte `snapshot.devicetvmsoftwareinventory`) | A build muda após a instalação e a reinicialização |
| KB de segurança, build corrigida, lançamento, substituição, reinicialização | Security Update Guide da Microsoft (MSRC), API pública `api.msrc.microsoft.com/sug/v2.0` (fonte `msrc.windows-server`, a cada 12 h) | Só `Security Update`: previews opcionais, hotpatch, rollups e avisos ADV (servicing stack) ficam fora |
| CVEs distintas, críticas e com exploit público por servidor | Defender `DeviceTvmSoftwareVulnerabilities` (todo software instalado) | `IsExploitAvailable` chega como 1/0 |
| KBs recomendados pelo Defender para CVEs do SO | Defender `DeviceTvmSoftwareVulnerabilities` | Evidência no detalhe; não decide a situação |

Ficam **fora do painel**, porque o Defender não fornece: data e hora da
instalação, falha de instalação, lista de pendências do Windows Update,
reinicialização pendente, última inicialização e tempo ligado. Obtê-los exige
coleta no próprio servidor (script por GPO). Pode ser feito numa etapa futura.

## Regras

1. **Escopo:** nome começa com `srv` e `OSPlatform` começa com `WindowsServer`.
   Os Windows 11 com nome SRV ficam fora.
2. **Build antes do KB:** cada servidor é comparado com as atualizações da sua
   build principal (14393 = 2016, 17763 = 2019, 20348 = 2022, 26100 = 2025),
   nunca com um KB único.
3. **Atualização de segurança mais recente aplicável:** o KB com a maior build
   corrigida para aquela build principal. **Lançamento Microsoft** é a data mais
   frequente entre os registros do KB no Security Update Guide. A menor data
   engana: a Microsoft anexa KBs novos a CVEs antigas, que mantêm a data original.
   Fuso original preservado, exibido em America/Sao_Paulo.
4. **Atualização refletida na build atual:** o KB cuja build corrigida é igual à
   do servidor (`exata`). Se a build ficar entre duas atualizações, vale a anterior
   (`equivalente`). Se ficar acima da última de segurança, é provável preview
   opcional ou atualização fora do ciclo (`acima_da_seguranca`), e o servidor
   continua em dia. Não é o histórico de instalação nem tem data de instalação.
5. **Pendente:** build menor que a da atualização mais recente. Como as
   atualizações são cumulativas, a pendência é **um** KB (o mais recente), que
   substitui os anteriores (`pending_superseded_count`).
6. **Pode exigir reinicialização:** informação da Microsoft (`rebootRequired`)
   sobre a atualização pendente. Não significa que o servidor esteja com
   reinicialização pendente. Valor ausente aparece como "Não informado pela
   Microsoft", nunca "Não".
7. **Atualização pendente mais antiga:** a primeira atualização de segurança da
   própria build que o servidor ainda não tem; a data indica desde quando ele está
   desatualizado. Não é o KB mais antigo recomendado pelo Defender, que pode citar
   KBs de outra build (ex.: KB de 2019 para um Windows Server 2022).
8. **Vulnerabilidades:** CVEs distintas por servidor de todo o software reportado
   pelo Defender, críticas e com exploit público disponível. Servidor em dia no
   Windows pode ter muitas CVEs de outros softwares. Sem snapshot concluído, o valor
   é desconhecido; não some servidores, porque a mesma CVE aparece em vários.
9. **Situação:** `em_dia`, `pendente`, `nao_determinado` (sem build ou sem
   catálogo para a build) ou `coleta_desatualizada` (sensor sem contato há mais de
   24 h, build coletada há mais de 36 h ou catálogo atualizado há mais de 48 h).
   Sem prazo de implantação definido pela organização, não existe "atrasado".
   O campo `update.days_since_latest_release` mostra há quantos dias a
   atualização pendente foi lançada, sem classificar.

## Modelo de dados

- `soc.windows_security_update` (PostgreSQL, migração 006): um registro por
  KB + build principal. A data de lançamento nunca avança para depois.
- `soc-windows-updates` (Elasticsearch): estado atual, um documento por
  `host.id` (DeviceId), com versão externa = horário do cálculo. Recalculado a
  cada hora (`windows.updates`).
- `soc-windows-updates-history-AAAA.MM`: foto diária com ID `DeviceId|AAAA-MM-DD`,
  sobrescrita no mesmo dia; retenção de ~12 meses (ILM `soc-history-retention`).

Campos principais: `host.name`, `windows.product`, `windows.version`,
`windows.build`, `update.latest_kb`, `update.latest_release_date`,
`update.installed_kb`, `update.installed_match`, `update.pending`,
`update.pending_kb`, `update.pending_superseded_count`,
`update.reboot_required`, `update.reboot_required_label`,
`update.days_since_latest_release`, `update.oldest_pending_kb`,
`update.oldest_pending_release_date`, `update.defender_recommended_kbs`,
`vulnerabilities.cve_count`, `vulnerabilities.critical_cve_count`,
`vulnerabilities.exploit_cve_count`, `vulnerabilities.instance_count`,
`status`, `status_label`, `status_reason`, `collection.device_last_seen`,
`collection.build_snapshot_at`, `collection.catalog_updated_at`,
`collection.collected_at`. Datas em ISO 8601 UTC.

## Implantação

1. VM-Docker: `docker compose stop collector`.
2. VM-PostgreSQL: `sudo bash postgres/migrate.sh` (aplica a 006).
3. VM-Docker, depois de `git pull`:

```bash
docker compose run --rm setup
docker compose build collector
docker compose restart logstash
docker compose up -d --no-deps collector
docker compose run --rm kibana-setup
```

O `kibana-setup` também define o fuso do espaço SOC como America/Sao_Paulo.
O primeiro cálculo completo sai depois do catálogo MSRC (cerca de 2 min) e do
snapshot de inventário de software; até lá os servidores aparecem como "Não
determinado" ou "Coleta desatualizada".

A VM-Docker precisa de saída HTTPS para `api.msrc.microsoft.com` (já validado).
