# Atualização: processos, conexões e exposição/proteção

Para ambiente que já recebeu a evolução de identidades/cobertura. A entrega é
local; os comandos abaixo serão executados pelo responsável nas duas VMs Ubuntu
26.04. A versão da Elastic Stack continua 9.5.5 e o PostgreSQL continua 18.

## O que chega

| Fonte | Frequência / histórico inicial | Uso |
|---|---|---|
| DeviceProcessEvents | 5 min / 1 h | Processo criado, argumentos, conta, hashes e iniciador |
| DeviceNetworkEvents | 5 min / 1 h | Endpoints local/remoto e processo responsável |
| DeviceInfo | 1 h / inventário existente | Exposição, valor do ativo e indicação de acesso pela internet, quando disponíveis |
| DeviceTvmSoftwareVulnerabilities + KB | 6 h / estado atual | CVEs, software, criticidade, CVSS e exploit público disponível |
| DeviceTvmSecureConfigurationAssessment + KB | 6 h / estado atual | Avaliações aplicáveis/conformes e descrição das configurações |

Processos e rede possuem também reconciliação defasada em 24 h, como as fontes
anteriores. Todos os servidores no filtro continuam sendo coletados: contém
`srv` ou `fisico`, exclui `note` ou `micro`, independentemente de maiúsculas e do
catálogo opcional. Incidentes e alertas continuam globais.

Proteção nesta entrega significa saúde do sensor e avaliações TVM, incluindo
avaliações de antivírus quando reportadas. Versão de assinatura, motor,
plataforma e modo operacional do antivírus exigem outra integração com a API
Defender for Endpoint; não são apresentados como se estivessem coletados aqui.

## 1. Preparar as duas VMs

Atualize os arquivos do repositório nas duas VMs, preservando `.env`, segredos,
certificados e cadastros locais de ativos/identidades. Na VM-Docker, na pasta
`docker/`, interrompa apenas o coletor enquanto aplica a migração:

```bash
docker compose stop collector
```

As consultas novas usam o mesmo endpoint Graph Advanced Hunting já existente.
Consulte as quatro consultas novas no portal Defender com acesso autorizado para
conferir disponibilidade das tabelas/licença. O teste local não valida o tenant.
Fontes TVM vêm habilitadas; tabela indisponível ou permissão insuficiente provoca
falha visível na respectiva fonte, preservando a última coleta bem-sucedida.

Se o tenant não oferecer TVM, defina `enabled: false` somente nas duas fontes
`snapshot.*` em `collector/config/sources.json` antes de iniciar. Processos,
conexões, logons e ASR continuam independentes. Nesse caso, a frente de postura
permanece sem cobertura; dashboards vazios não significam ambiente saudável.
Não é necessário conceder permissões da API MDE para esta entrega.

## 2. VM-PostgreSQL — obrigatório

Na raiz da cópia atualizada do repositório:

```bash
sudo bash postgres/migrate.sh
```

A migração `004_posture_state` cria estado atual de postura e amplia os tipos
aceitos na publicação. O script aplica apenas migrações pendentes. Não execute
o coletor novo antes desta etapa. Não é necessário alterar TLS/certificados nem
repetir o bootstrap do banco para esta atualização.

## 3. VM-Docker — obrigatório

Na pasta `docker/`, ajuste `COLLECTOR_VERSION=0.3.0` no `.env` existente, mantendo
os demais valores. Aplique mappings/permissões, construa e recrie consumidores e
importe os objetos Kibana:

```bash
docker compose run --rm setup
docker compose build collector logstash
docker compose up -d --no-deps logstash collector
docker compose run --rm kibana-setup
docker compose ps
```

O setup adiciona mappings e o template do índice atual `soc-posture`, criado na
primeira ingestão de postura, preservando índices
existentes. Há duas telas novas no espaço `soc`: **Processos e conexões** e
**Exposição e proteção**. A importação sobrescreve objetos dos IDs geridos pelo
projeto; preserve personalizações em IDs próprios. Permanecem as oito regras em
observação e os perfis observer/analyst/admin.

Nenhuma republicação de eventos antigos é obrigatória. O coletor inicia as novas
fontes com uma hora de histórico, sem apagar checkpoints das fontes anteriores.

## 4. Conferir dados e capacidade

- Confira execuções/checkpoints de processos, rede e snapshots no painel de
  cobertura e na tabela de atualização de fontes do painel de exposição.
- Investigue um servidor por `host.id`. Confira conta/linha de comando, processo
  criado/pai e conexões. O identificador de processo só permite correlação quando
  fornecido pelo Defender; PID isolado não é identificador permanente.
- Confirme atualização das duas fontes TVM. Itens atuais usam
  `soc.posture.active: true`. Um snapshot pode retornar zero linhas; isso informa
  apenas que a API não reportou itens no escopo daquela consulta.
- Observe crescimento PG/ES, espaço livre, duração das coletas, throttling e
  defasagem após algumas horas e novamente após 24 h. Rede e processos costumam
  ter volume maior; a capacidade real depende do uso dos servidores.

Snapshots possuem limite conservador de 10.000 linhas por fonte, antes de
deduplicar. Atingir o limite recusa a atualização inteira e registra falha. Não
aumente apenas `maxRows`: as consultas também possuem limite explícito; a
expansão deve considerar particionamento e completude da consulta. O painel deve
ser lido junto da última coleta bem-sucedida e da data de avaliação reportada.

Conexões são eventos de telemetria; não medem bytes transferidos nem comprovam
exfiltração. Endpoint remoto público não comprova malícia. Exploit público
disponível não comprova exploração no ambiente. A indicação `IsInternetFacing`
representa a observação do Defender, sem substituir inventário de firewall/NAT.

Um item ausente de um snapshot completo passa a `no_longer_reported`; pode ter
sido corrigido, removido ou deixado de ser avaliado. Falha, tabela ausente ou
resultado incompleto não retira itens atuais. Resultados anteriores podem ficar
desatualizados; consulte as datas antes de decidir sobre o risco.

## 5. Reversão preservando dados

Pare o coletor, volte aos arquivos/imagens anteriores e recrie coletor/Logstash.
Mantenha banco, volumes, CA, checkpoints e a migração aditiva 004. Não use
`down -v`, `DROP` ou exclusão de índices como parte da reversão. Para interromper
apenas as fontes novas, desabilite suas entradas em `sources.json` e reinicie o
coletor; isso conserva dados já coletados e as fontes anteriores.

## Referências

- [DeviceProcessEvents](https://learn.microsoft.com/defender-xdr/advanced-hunting-deviceprocessevents-table)
- [DeviceNetworkEvents](https://learn.microsoft.com/defender-xdr/advanced-hunting-devicenetworkevents-table)
- [DeviceInfo](https://learn.microsoft.com/defender-xdr/advanced-hunting-deviceinfo-table)
- [Vulnerabilidades TVM](https://learn.microsoft.com/defender-xdr/advanced-hunting-devicetvmsoftwarevulnerabilities-table)
- [Avaliações de configuração](https://learn.microsoft.com/defender-xdr/advanced-hunting-devicetvmsecureconfigurationassessment-table)
