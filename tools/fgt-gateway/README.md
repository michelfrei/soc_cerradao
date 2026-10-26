# fgt-gateway — consultas somente leitura ao FortiGate pelo Claude

```
Notebook: Claude → MCP local (mcp.mjs) ──HTTPS+mTLS:8443──► Servidor 172.16.159.140: fgt-gateway (server.mjs, conta svc_fgtgw)
                                                              └─ ssh.exe (chave e known_hosts locais) ──► FortiGate 172.16.0.1:40022 (claude / soc_readonly)
```

## Segurança

- **Lista fechada** (`lib/commands.mjs`): `status`, `interfaces_status`, `interfaces_config`, `routes`,
  `policies` e `policy <id inteiro>`. Não há texto livre; qualquer outra ferramenta ou parâmetro é recusado.
- **Chave SSH** gerada no servidor, sem frase, com dono e leitura só de `svc_fgtgw`. Não sai do servidor
  e não aparece em respostas nem no log. A chave antiga com frase não é usada.
- **Identidade do FortiGate**: `StrictHostKeyChecking=yes` com `known_hosts` próprio, copiado do
  known_hosts já validado do administrador. Identidade diferente faz a consulta falhar.
- **Notebook ↔ servidor**: TLS 1.2+ com autenticação mútua. CA própria em PEM gerada com OpenSSL (não
  instalada como confiável no Windows; a chave da CA é apagada após emitir os certificados);
  o servidor só aceita o certificado de cliente emitido para `fgt-client-<usuário>`; o cliente só confia
  no certificado do servidor emitido por essa CA. Firewall do Windows: porta 8443 só de 172.19.12.0/22.
- **Conta `svc_fgtgw`**: local, sem administrador, logon interativo e RDP negados, senha aleatória que
  ninguém conhece (usada só no registro da tarefa agendada).
- **Saída**: linhas `set <senha|psksecret|...-key>` e valores `ENC ...` viram `<removido>`.
- **Auditoria**: `C:\ProgramData\fgt-gateway\logs\audit-AAAA-MM.jsonl` com cliente, ferramenta, comando,
  duração e tamanho; sem o conteúdo das respostas.

## Instalação no servidor (Administrador)

1. Instale o Node.js LTS (nodejs.org), o Git for Windows (traz o `openssl.exe`) e confirme o cliente
   OpenSSH (`ssh -V`). Compatível com Windows Server 2016 (OpenSSH do pacote Win32-OpenSSH) e posteriores.
2. Obtenha este repositório no servidor e rode:
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\tools\fgt-gateway\install-server.ps1 -ClientName acalixto
   ```
3. No FortiGate (conta com permissão sobre o usuário `claude`), cadastre a chave pública exibida no fim:
   ```
   config system admin
       edit "claude"
           set ssh-public-key2 "<chave pública exibida>"
           set trusthost2 172.16.159.140 255.255.255.255
       next
   end
   ```
4. Copie `C:\ProgramData\fgt-gateway\client-bundle` para o notebook e apague-a do servidor.

## Instalação no notebook

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\fgt-gateway\install-client.ps1 -BundlePath <pasta copiada>
```

O Claude Code usa o `.mcp.json` do projeto (servidor `fortigate`); o script também registra o conector no
Claude Desktop, se instalado. Reinicie o Claude e aprove o servidor MCP `fortigate`.

## Testes

```bash
node --test tools/fgt-gateway/test/*.test.mjs
```
Geram CA e certificados temporários com OpenSSL e usam um SSH falso: validam mTLS, recusa sem
certificado ou de outra CA, lista fechada, remoção de segredos e auditoria sem conteúdo.
