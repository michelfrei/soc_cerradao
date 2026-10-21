# Implantação da evolução SOC — duas VMs

Destino: Ubuntu 26.04 com PostgreSQL 18 nativo na VM-PG; Ubuntu 26.04 com
Elasticsearch, Kibana, Logstash e coletor em Docker Compose na VM-Docker.
Este documento prepara a aplicação pelo responsável. Os comandos abaixo não são
executados automaticamente e devem usar os endereços reais do ambiente.
Não há criação de credenciais de usuários neste pacote.

## 1. Aplicar a migração PostgreSQL

Na VM-PG, a partir da raiz do repositório atualizado:

```bash
sudo bash postgres/migrate.sh
sudo -u postgres psql -X -d soc -c 'TABLE soc.schema_migrations'
```

Confirme a migração `003` antes de atualizar a stack consumidora. Não recrie o
banco, não apague checkpoints e preserve as migrações anteriores. A nova coleta
e as consultas operacionais dependem da estrutura correspondente a esta versão.

## 2. TLS PostgreSQL com validação do servidor (opcional nesta atualização)

O padrão `SOC_PG_SSLMODE=require` permanece para compatibilidade. Ele cifra a
conexão, mas não valida a identidade do servidor. Para ativar `verify-full`, o
valor de `SOC_PG_HOST` deve constar como DNS ou IP no SAN do certificado e ser
resolvido pela VM-Docker e pelos containers. Não use o nome de exemplo como nome
real. Se conectar por IP, inclua esse IP em `PG_TLS_IPS`.

Na VM-PG, substitua os valores entre `< >`. Informe uma ou ambas as variáveis SAN:

```bash
sudo PG_TLS_DNS='<dns-real-da-vm-pg>' PG_TLS_IPS='<ip-real-da-vm-pg>' \
  bash postgres/configure-tls.sh
```

O script prepara o certificado em `/etc/postgresql/18/main/soc-tls/` e mantém a
CA privada em `/root/soc-pg-ca/`, fora do repositório. A chave privada da CA é
root:root 600; a chave do servidor é root:postgres 640. Só o certificado público
da CA será copiado. O padrão não modifica a configuração TLS ativa nem recarrega
o banco. Uma nova execução preserva certificado válido com os mesmos SAN; a
renovação por vencimento usa a mesma CA. Para mudança deliberada de SAN ou
renovação antecipada, acrescente `PG_TLS_RENEW=1`.

Depois de conferir os SAN e a validade, instale a configuração:

```bash
sudo PG_TLS_DNS='<dns-real-da-vm-pg>' PG_TLS_IPS='<ip-real-da-vm-pg>' APPLY_TLS=1 \
  bash postgres/configure-tls.sh
sudo systemctl reload postgresql@18-main
sudo -u postgres psql -X -d postgres -c 'SHOW ssl_cert_file' -c 'SHOW ssl_key_file'
```

`APPLY_TLS=1` aceita o certificado padrão snakeoil do Ubuntu ou o caminho já
gerido pelo script. Se houver certificado corporativo personalizado, o script
recusa substituir a configuração ativa: mantenha a PKI existente e instale a
CA pública apropriada nos consumidores. Ele também recusa recriar uma CA quando
há somente metade do par chave/certificado. Expiração da própria CA exige uma
rotação planejada de confiança; não exclua a CA para forçar a renovação.

Copie **somente** `/root/soc-pg-ca/ca.crt` da VM-PG para
`docker/certs/postgres/ca.crt` na VM-Docker, por um canal administrativo
autenticado. Para usar um usuário sem acesso a `/root`, prepare uma cópia pública
temporária e confira o SHA-256 nas duas pontas. O arquivo é público, mas sua
integridade deve ser protegida. Nunca transfira `ca.key` ou `server.key`.

Na VM-Docker:

```bash
chmod 644 docker/certs/postgres/ca.crt
```

Edite `docker/.env`: `SOC_PG_HOST` deve corresponder ao SAN; altere
`SOC_PG_SSLMODE=verify-full`. A pasta é montada somente leitura em
`/usr/share/logstash/pg-ca` e `/app/pg-ca`. JDBC usa
`SOC_PG_SSLROOTCERT=/usr/share/logstash/pg-ca/ca.crt`; o coletor só fornece
`PGSSLROOTCERT_FILE=/app/pg-ca/ca.crt` ao Node quando o modo é `verify-full`.
Sem a CA, `verify-full` falha; não há fallback automático para conexão sem
validação. Em `require`, o coletor não tenta ler o arquivo ausente.

Renove o certificado antes do vencimento, preserve a CA e recarregue PostgreSQL.
Renovar sob a mesma CA não exige trocar o arquivo de confiança nos clientes.

## 3. Preparar o host e migrar a distribuição dos certificados Elastic

O preparo do host agora estabelece `vm.max_map_count=1048576`, conforme a
[documentação de Docker do Elastic](https://www.elastic.co/docs/deploy-manage/deploy/self-managed/install-elasticsearch-docker-prod).
Execute na VM-Docker após revisar `docker/.env` e os segredos existentes:

No `.env` existente, defina `COLLECTOR_VERSION=0.2.0` antes do build. Não substitua
seu `.env` pelo arquivo de exemplo: mantenha endereços, senhas e chaves atuais.

```bash
sudo bash docker/host/prepare-docker-host.sh
cd docker
docker compose config -q
docker compose build collector logstash
```

O nome do projeto Compose continua `soc`. Preserve `soc_ca_private` e `soc_certs`:
o primeiro contém a CA privada; o segundo mantém os certificados e as chaves
legados para o gerador. Na atualização, o gerador copia os mesmos arquivos para
volumes separados. Não é necessário apagar volume, gerar outra CA ou reinstalar
a CA nas estações dos analistas.

| Volume | Consumidores | Conteúdo |
|---|---|---|
| `soc_ca_private` | apenas gerador `certs` | CA privada existente |
| `soc_certs` | apenas gerador `certs` | conjunto legado preservado |
| `soc_certs_public` | consumidores e setups | somente `ca.crt` público |
| `soc_certs_es` | gerador e Elasticsearch | certificado/chave do ES |
| `soc_certs_kibana` | gerador e Kibana | certificado/chave do Kibana |

Em janela de atualização, pare os consumidores enquanto o gerador publica os
volumes separados e recrie os containers com os novos mounts:

```bash
docker compose stop collector logstash kibana es01
docker compose run --rm certs
docker compose up -d es01
docker compose run --rm setup
docker compose up -d kibana logstash collector
docker compose ps
docker compose run --rm kibana-setup
```

O gerador recusa trocar a CA quando encontra certificados legados sem sua chave
de CA; restaure o conjunto correto. Se encontrar arquivos parciais ou CA pública
divergente, também falha em vez de substituir a confiança. Os volumes antigos
permanecem preservados. A política ILM continua a retenção que já está versionada.

## 4. Espaço SOC e acesso de pessoas

O `kibana-setup` cria o espaço de id `soc`, importa data views, dashboards e regras
sob `/s/soc`, e aplica os papéis de `kibana/roles/` pela API Kibana. Abra
`https://<endereco-real-kibana>:5601/s/soc/app/dashboards`. Os links internos dos
dashboards também apontam para esse espaço. `KIBANA_PUBLIC_URL` permanece a URL
base do servidor, sem acrescentar `/s/soc`.

| Papel | Acesso funcional no espaço `soc` |
|---|---|
| `soc_reader` / `soc_observer` | dashboards somente leitura |
| `soc_analyst` | dashboards, Discover, leitura das regras, triagem de alertas e gerenciamento de Cases |
| `soc_admin` | administração funcional dos dashboards, consultas, data views, regras, alertas e Cases SOC |

Os índices `soc-*` são somente leitura para os três níveis. Observadores também
podem ler os índices de alertas SOC para renderizar o painel operacional, inclusive
por API Elasticsearch; não recebem a interface de triagem nem permissão de escrita.
Analistas podem
atualizar alertas apenas do espaço SOC; administradores funcionais também
gerenciam índices de alertas/listas desse espaço e suas próprias API keys.
Não há `superuser`, `manage_security`, `run_as`, acesso a todos os espaços ou
privilégios de alteração sobre os eventos históricos nesses papéis. O papel
`soc_admin` não administra usuários nem inicializa um cluster. O bootstrap faz a
inicialização necessária com `elastic`.

Um administrador da plataforma deve criar usuários nominais e atribuir o papel
correto. Não use `elastic` no cotidiano e evite adicionar papéis amplos aos mesmos
usuários, pois permissões de múltiplos papéis se somam. Antes da adoção, teste com
uma conta nominal de cada nível: observer abre os cinco dashboards e não edita;
analyst usa Discover, altera o status de um alerta de laboratório e cria um Case,
mas não modifica regras; admin edita uma regra SOC, sem administrar usuários ou
dados do cluster. Esses testes precisam acontecer na implantação real.

As regras herdam as permissões do usuário que as editou/importou por meio de API
keys. O bootstrap inicial usa `elastic`; após criar o usuário nominal `soc_admin`,
atualize as API keys das regras como esse usuário em Security → Rules → seleção
das regras SOC → Update API keys. Confirme a execução nesse contexto antes de
encerrar o bootstrap. Uma nova importação com `elastic` requer repetir essa etapa.
Não compartilhe essas chaves nem senhas em comandos ou documentação.

### Compatibilidade com o espaço default

Objetos, regras e alertas antigos do espaço `default` não são apagados, movidos ou
convertidos automaticamente. Os alertas históricos permanecem no espaço que os
gerou. As novas regras SOC geram alertas em `.alerts-security.alerts-soc`; os papéis
novos não concedem acesso a `.alerts-security.alerts-default`.

Depois de conferir os novos dashboards e a execução das regras no espaço SOC,
desative manualmente as regras antigas equivalentes no espaço default para
evitar duas execuções. Não apague seus alertas. Durante a transição, use acesso
administrativo já existente para consultar o histórico antigo. Ao reaplicar
`kibana-setup`, os objetos/regras de ids geridos no espaço SOC são sobrescritos;
personalizações de interface devem usar outro id ou ser versionadas no pacote.

O papel legado `soc_reader` será atualizado para dashboards no espaço SOC.
Usuários que dependam dele no espaço default devem ter sua transição avaliada
antes de rodar o setup. Nenhum usuário é criado ou removido pelo script.

Os ids dos recursos foram conferidos no
[código oficial Kibana v9.5.5](https://github.com/elastic/kibana/blob/v9.5.5/x-pack/solutions/security/packages/features/src/constants.ts).
O setup também verifica `/api/features` e interrompe se a versão não oferecer os
recursos previstos; não troca por privilégios globais como alternativa.
Referências: [privilégios Kibana](https://www.elastic.co/docs/deploy-manage/users-roles/cluster-or-deployment-auth/kibana-privileges)
e [permissões de detecções](https://www.elastic.co/docs/solutions/security/detect-and-alert/detections-requirements).

## 5. Verificar e reverter sem apagar dados

Confira a saúde dos containers, ausência de erros TLS nos logs, avanço dos
checkpoints e chegada dos eventos antes de encerrar a janela. Se ativou
`verify-full`, execute uma conexão de teste com o mesmo host e CA dos consumidores
e confirme que um host incompatível é recusado. Os testes locais não comprovam
DNS, firewall ou certificados das VMs.

Para falha na ativação TLS, mantenha os dados e a CA: pode-se voltar
temporariamente `SOC_PG_SSLMODE=require` no `.env` e recriar apenas collector e
Logstash, registrando que a validação de identidade está suspensa. Se a mudança
for a configuração do servidor, restaure o arquivo anterior de `conf.d` e o
conjunto de certificados preservado pelo script, depois recarregue PostgreSQL.
Não exclua a CA para tentar corrigir erro de confiança.

Para falha da stack, volte à versão de arquivos/imagens previamente conhecida e
recrie os serviços, preservando os bind mounts de dados, checkpoints e todos os
volumes. O conjunto legado `soc_certs` continua disponível para a configuração
anterior. Não execute `down -v` nem remova volumes. Não reverta a migração de banco
com `DROP`: mantenha a estrutura aditiva e avalie compatibilidade da versão anterior.
Para falha do espaço SOC, os objetos e alertas do default continuam disponíveis;
reabilite regras antigas somente após desativar as equivalentes do SOC.

Nenhuma alteração de backup, quarentena ou política de atrasos faz parte desta
etapa. Não há deploy remoto, execução nas VMs ou autenticação no Graph nesta entrega.

## 6. Cadastros opcionais, histórico e medição

`collector/config/assets.json` começa vazio. Cadastre os servidores esperados
com `name` obrigatório e `id` opcional, owner/environment/criticality quando
conhecidos. A lista não restringe os logs dos demais nomes incluídos no escopo.
`logstash/config/identities.json` começa com accounts vazio; classifique pessoas
e serviços explicitamente seguindo [IDENTIDADES.md](IDENTIDADES.md). Não há
sincronização automática com AD/Entra nem descoberta de ativos nunca onboarded.

Reinicie o coletor após alterar assets; reinicie Logstash após alterar identities.
As consultas incluem nomes com srv/fisico e excluem sempre note/micro. Esses termos
não diferenciam maiúsculas. Incidentes e alertas do Graph continuam globais.

As regras v2 dependem dos campos novos. Para construir uma base histórica, escolha
um período já presente no PostgreSQL e use a republicação documentada no runbook,
com o novo Logstash ativo. Não apague checkpoints para essa finalidade. Sem essa
etapa, a base das regras new_terms será formada a partir dos eventos novos; haverá
mais novidades no início. A republicação também reavalia regras por event.ingested,
conforme as limitações já registradas em DETECCOES.md.

Métricas PG/ES são automáticas por minuto. Para medir CPU/memória das próprias VMs:

```bash
# Na VM-Docker, na raiz do repositório:
bash scripts/capacity-report.sh docker
# Na VM-PG, na raiz do repositório:
bash scripts/capacity-report.sh postgres
```

Esse relatório é somente leitura e representa uma amostra. Os dashboards não
estimam CPU/RAM das VMs a partir da quantidade de eventos.
