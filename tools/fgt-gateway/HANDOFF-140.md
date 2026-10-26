# Continuação no servidor 172.16.159.140 — implantação do fgt-gateway

Prompt para o Claude que roda **no servidor 172.16.159.140**. Leia este arquivo inteiro antes de agir.

## Contexto

Projeto SOC da Usina Cerradão (repositório `soc_cerradao`). Objetivo: o Claude no notebook do Arthur
(172.19.12.46, rede 172.19.12.0/22) consulta o FortiGate em modo somente leitura por este fluxo:

```
Notebook: Claude → MCP local (tools/fgt-gateway/mcp.mjs) ──HTTPS + mTLS :8443──►
Servidor 172.16.159.140: fgt-gateway (tools/fgt-gateway/server.mjs), conta local svc_fgtgw ──SSH──►
FortiGate 172.16.0.1:40022, usuário claude, perfil soc_readonly (get/show)
```

O código, os testes e os instaladores já estão prontos e testados localmente
(`node --test tools/fgt-gateway/test/*.test.mjs`). Leia `tools/fgt-gateway/README.md`,
`server.mjs`, `lib/commands.mjs` e `install-server.ps1` antes de executar.

## Regras (obrigatórias)

- Não digite senhas nem frases de proteção de chave. Quando um comando pedir, **peça ao usuário para
  digitar**. Não peça que ele cole senhas no chat.
- Não abra, copie, exiba nem registre chaves privadas. A chave atual
  `C:\Users\administrator\.ssh\fortigate_claude_rsa` (com frase) **é preservada** e não é usada pelo
  serviço; o instalador gera uma chave nova sem frase em `C:\ProgramData\fgt-gateway\keys`, legível só por
  `svc_fgtgw`.
- Preserve a chave e o acesso SSH existentes até o serviço funcionar sob `svc_fgtgw` e passar no teste
  após reiniciar o servidor. Só então sugira aposentar a chave antiga — sem apagar nada sem confirmação.
- No FortiGate, só comandos `get`/`show`. Alterações no FortiGate (cadastrar a chave pública) são feitas
  **pelo usuário**; você prepara o comando exato.
- Não altere o código do repositório sem necessidade comprovada; se alterar, rode os testes e explique.
- Peça confirmação antes de ações difíceis de desfazer (criar conta, regra de firewall, tarefa agendada) —
  o instalador faz isso; explique o que ele fará antes de executá-lo.

## Etapas

1. **Pré-validação neste servidor** (PowerShell como Administrador), mostrando a saída real:
   - `node -v` e `(Get-Command node).Source`
   - `& "$env:WINDIR\System32\OpenSSH\ssh.exe" -V`
   - `Test-Path C:\Users\administrator\.ssh\fortigate_claude_rsa` (só a existência; não abra o arquivo)
   - entrada `[172.16.0.1]:40022` em `C:\Users\administrator\.ssh\known_hosts` e a impressão digital
     (`ssh-keygen -l -f` sobre um arquivo temporário com essas linhas)
   - acesso SSH atual: o **usuário** executa
     `ssh -i C:\Users\administrator\.ssh\fortigate_claude_rsa -p 40022 -o StrictHostKeyChecking=yes claude@172.16.0.1 "get system status"`
     e digita a frase quando pedida.
2. **Posições de chave no FortiGate**: na mesma sessão SSH do usuário,
   `show system admin claude | grep ssh-public-key` e `show system admin claude | grep trusthost`.
   Há três posições (`ssh-public-key1..3`). Identifique quais estão ocupadas (a do notebook termina em
   `claude-fortigate@NOTE438-20261026`; a atual do servidor é a `fortigate_claude_rsa`). Escolha uma posição
   **livre**. Se não houver, pare e pergunte ao usuário qual substituir — não sobrescreva chave em uso.
   Confirme que 172.16.159.140 está num `trusthost`.
3. **Instalação**: `powershell -ExecutionPolicy Bypass -File C:\soc_cerradao\tools\fgt-gateway\install-server.ps1 -ClientName acalixto`
   (o padrão de `-ServerIp` já é 172.16.159.140). Mostre ao usuário a chave pública e as impressões digitais
   do final da saída.
4. **FortiGate (usuário executa)**:
   `config system admin` → `edit "claude"` → `set ssh-public-key<N> "<chave pública do serviço>"` → `next` → `end`,
   com N = posição livre do passo 2.
5. **Teste do serviço neste servidor**:
   - `Get-ScheduledTask fgt-gateway | Select-Object State`, `Get-ScheduledTaskInfo fgt-gateway` (LastTaskResult 0)
   - `Get-NetTCPConnection -LocalPort 8443 -State Listen`
   - teste SSH **como o serviço** sem expor segredos: a consulta real virá pelo notebook; aqui, confira só
     que o log `C:\ProgramData\fgt-gateway\logs\audit-*.jsonl` registra a consulta depois do passo 7.
   - Se algo falhar, diagnostique pelos logs/eventos sem exibir conteúdo de chaves ou arquivos `*.pass`.
6. **Pacote do cliente**: oriente o usuário a copiar `C:\ProgramData\fgt-gateway\client-bundle` para o
   notebook por um meio interno e, no notebook (usuário comum, não administrador):
   `powershell -ExecutionPolicy Bypass -File C:\Projetos\soc_cerradao\tools\fgt-gateway\install-client.ps1 -BundlePath <pasta>`.
   Depois, apagar a pasta `client-bundle` daqui e a cópia temporária do notebook.
7. **Validação**: o Claude do notebook chama `fortigate_status`. Confira aqui o registro em
   `audit-*.jsonl` (resultado `ok`, sem conteúdo). Peça um teste de recusa (ferramenta inexistente) e
   confira o registro `refused`.
8. **Reinício**: com autorização do usuário, reinicie o servidor; depois confirme a tarefa `fgt-gateway` em
   execução como `svc_fgtgw`, a porta 8443 escutando e uma nova consulta `ok` vinda do notebook.

Ao final, resuma o que foi validado (com as saídas), o que ficou pendente e a recomendação sobre a chave antiga.
