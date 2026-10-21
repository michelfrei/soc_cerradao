# Identidades e escopo

## Regra de nomes

Os logs de hunting e o inventário incluem nomes com `srv` **ou** `fisico` e
excluem nomes com `note` **ou** `micro`, ignorando maiúsculas. A exclusão sempre
prevalece: `srv-note01` e `fisico-micro01` estão fora. Não existe lista de ativos
que restrinja os demais servidores desse escopo. Incidentes e alertas do Graph
continuam abrangendo o tenant, pois podem envolver múltiplos dispositivos.

As consultas aplicam a regra antes da transferência e o Logstash aplica a mesma
regra antes de indexar eventos de hunting/inventário. Dados antigos já indexados
não são apagados: as telas e regras novas também aplicam o escopo.

## Chaves

- `soc.identity.key`: SID quando válido; alternativa qualificada por nome. SIDs
  conhecidos de SYSTEM/serviços são qualificados pelo servidor.
- `soc.identity.correlation_key`: domínio + conta, ou servidor + conta local/sem
  domínio; SID é alternativa quando não há nome. É usada nas regras e contagens.
  Isso permite unir uma falha sem SID a um sucesso com SID quando ambos informam
  o mesmo domínio/conta. Não une domínios diferentes nem contas locais homônimas.
- `soc.identity.display`: apresentação legível; não é chave de correlação.
- `scope`: local, domain ou unknown. Domínio ausente não é adivinhado.
- `confidence`: base usada na correlação (sid, domain_name, host_name, unknown).
- `has_sid`: disponibilidade de SID válido no evento.
- `is_local_admin`: contexto IsLocalAdmin do evento; não prova Domain Admin.

Contas não classificadas permanecem `unknown`. Sufixo `$` identifica máquina;
autoridades conhecidas identificam sistema. Nomes como `svc_*` não comprovam
conta de serviço. Não há consulta automática ao AD/Entra nesta versão, nem união
automática de UPN, NetBIOS e contas renomeadas sem evidência de equivalência.

## Cadastro opcional de classificação

Edite `logstash/config/identities.json` e reinicie apenas o Logstash. Não coloque
senhas neste arquivo. Exemplo fictício (não vem habilitado):

```json
{
  "accounts": [
    {"domain":"dominio.exemplo", "name":"conta_servico_exemplo", "type":"service", "privileged":false, "owner":"Equipe responsável"},
    {"host_id":"id-defender-do-servidor", "name":"administrador_local_exemplo", "type":"person", "privileged":true}
  ]
}
```

Cada entrada precisa de `type` (`person`, `service`, `machine`, `system`, `unknown`)
e de `sid` ou `name` com `domain`/`host_id`. Campos opcionais: `label`, `owner`,
`privileged`. Entradas mais específicas prevalecem; evite sobreposições ambíguas.
Classificação só altera campos derivados, não o payload original do Defender.

## Histórico e regras

Novos campos entram automaticamente nos eventos novos. Eventos antigos precisam
de republicação do período que se desejar investigar com as novas identidades.
As regras v2 exigem os campos de correlação para evitar resultados ambíguos de
documentos legados. Sem dados enriquecidos não há base para alertas de pares novos.
As janelas de 14 dias também precisam de histórico suficiente para estabilizar.

O histórico representa observações, não autorização de acesso. Conta nova em
servidor significa comportamento a avaliar, não acesso automaticamente indevido.
