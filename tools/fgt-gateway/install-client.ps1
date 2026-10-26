<#
Instala o certificado de cliente do fgt-gateway no notebook (sem privilégio de administrador).
Copia client-bundle para %USERPROFILE%\.fgt-gateway com acesso só do usuário atual e, se o
Claude Desktop (chat) estiver instalado, registra o conector MCP no claude_desktop_config.json.
No Claude Code, o conector já vem declarado no .mcp.json do projeto.

Exemplo:
  powershell -ExecutionPolicy Bypass -File .\install-client.ps1 -BundlePath D:\client-bundle
#>
param([Parameter(Mandatory = $true)][string]$BundlePath)
$ErrorActionPreference = 'Stop'
foreach ($f in 'ca.pem', 'client.pfx', 'client.pass', 'client.json') {
  if (-not (Test-Path (Join-Path $BundlePath $f))) { throw "Arquivo ausente no pacote: $f" }
}
$dest = Join-Path $env:USERPROFILE '.fgt-gateway'
New-Item -ItemType Directory -Force $dest | Out-Null
Copy-Item (Join-Path $BundlePath '*') $dest -Force
icacls $dest /inheritance:r /grant:r "$($env:USERNAME):(OI)(CI)F" | Out-Null
Get-ChildItem $dest | ForEach-Object { icacls $_.FullName /inheritance:r /grant:r "$($env:USERNAME):F" | Out-Null }
Write-Host "Certificado de cliente instalado em $dest (acesso só de $env:USERNAME)."

$mcp = Join-Path $PSScriptRoot 'mcp.mjs'
$node = (Get-Command node -ErrorAction SilentlyContinue).Source
$desktop = Join-Path $env:APPDATA 'Claude\claude_desktop_config.json'
if ($node -and (Test-Path (Split-Path $desktop))) {
  $cfg = if (Test-Path $desktop) { Get-Content $desktop -Raw | ConvertFrom-Json } else { [pscustomobject]@{} }
  if (-not $cfg.PSObject.Properties['mcpServers']) { $cfg | Add-Member -NotePropertyName mcpServers -NotePropertyValue ([pscustomobject]@{}) }
  $entry = [pscustomobject]@{ command = $node; args = @($mcp) }
  if ($cfg.mcpServers.PSObject.Properties['fortigate']) { $cfg.mcpServers.fortigate = $entry } else { $cfg.mcpServers | Add-Member -NotePropertyName fortigate -NotePropertyValue $entry }
  $cfg | ConvertTo-Json -Depth 10 | Set-Content $desktop -Encoding utf8
  Write-Host "Conector registrado no Claude Desktop ($desktop). Reinicie o Claude Desktop."
}
Write-Host 'Apague a pasta client-bundle do servidor depois de copiar.'
