# Atualização: insights de remediação (coletor 0.4.0)

Para ambiente que já recebeu processos/exposição (migração 004). Entrega local;
os comandos serão executados pelo responsável nas VMs. Contrato e regras em
[INSIGHTS-REMEDIACAO.md](INSIGHTS-REMEDIACAO.md).

## O que chega

| Item | Uso |
|---|---|
| Fonte `snapshot.devicetvmsoftwareinventory` (6 h) | Software com fim de suporte informado pelo Defender |
| Fonte `insights.remediation` (6 h, sem Graph) | Agrupa a postura atual em ações e publica em `soc-insights` |
| Migração `005_remediation_insights` | Tabela `soc.remediation_insight`, novos tipos de publicação/postura, `soc.republish_insights()` |
| `collector/config/remediation-catalog.json` | GPOs e ações validadas; vínculos scid confirmados pela equipe |
| Dashboard **SOC - Remediação** e data view `soc-insights` | Fila priorizada, GPOs propostas, investigações e detalhes |

Não há nova permissão Graph: a consulta nova usa o mesmo Advanced Hunting.

## 1. VM-Docker: parar o coletor

```bash
docker compose stop collector
```

## 2. VM-PostgreSQL — obrigatório antes do coletor

```bash
sudo bash postgres/migrate.sh
```

## 3. VM-Docker

No `.env`, ajuste `COLLECTOR_VERSION=0.4.0`. Depois:

```bash
docker compose run --rm setup
docker compose build collector
docker compose up -d --no-deps logstash collector
docker compose run --rm kibana-setup
docker compose ps
```

O setup cria o component template `soc-insights-mappings`, o template do índice
`soc-insights` e acrescenta os campos de fim de suporte em `soc-posture`. O
Logstash precisa ser recriado para carregar o `normalize.rb` novo.

O primeiro cálculo ocorre poucos segundos após a subida, mas só tem sucesso
depois que os dois snapshots TVM tiverem ao menos uma execução concluída. Até lá
a fonte registra falha "sem snapshot concluído", o que é esperado. Sem o
inventário de software concluído, os insights saem com a lacuna "fim de suporte
ainda não coletado".

## 4. Conferir

- Painel **Cobertura e capacidade** / tabela de execuções: `snapshot.devicetvmsoftwareinventory`
  e `insights.remediation` com status success.
- Painel **SOC - Remediação**: fila priorizada, tipos e GPOs. Confira `data_gaps`.
- Em Investigação, rode a consulta de scid de [INSIGHTS-REMEDIACAO.md](INSIGHTS-REMEDIACAO.md),
  confirme a correspondência e inclua os scid em `configuration_ids` do catálogo.
  Reinicie apenas o coletor; o próximo cálculo move os blocos para GPO.
  Para recalcular na hora, reinicie o coletor (o cálculo roda logo após a subida).

## 5. Reversão preservando dados

Volte aos arquivos/imagem 0.3.0 e recrie coletor e Logstash. A migração 005 é
aditiva e pode permanecer. Para desligar só os insights, `enabled: false` em
`insights.remediation` (e, se quiser, na fonte de inventário de software). Não
use `down -v`, `DROP` ou exclusão de índices. Para reconstruir `soc-insights`:

```sql
SELECT soc.republish_insights();
```
